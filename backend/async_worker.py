import os
import math
import json
import random
from datetime import datetime, timedelta

from celery import Celery, Task, chord
from celery.utils.log import get_task_logger
import psycopg2.extras

from serialization import deserialize_filters, load_public_key
from database import *
from settings import Config as config

from phe import paillier
import anonlink

celery = Celery('tasks',
                broker=config.BROKER_URL,
                backend=config.CELERY_RESULT_BACKEND
                )
celery.conf.CELERY_TASK_SERIALIZER = 'json'
celery.conf.CELERY_ACCEPT_CONTENT = ['json']
celery.conf.CELERY_RESULT_SERIALIZER = 'json'

logger = get_task_logger(__name__)
logger.info("Setting up celery...")


def convert_mapping_to_list(permutation):
    """Convert the permutation from a dict mapping into a list"""
    l = len(permutation)

    perm_list = []
    for j in range(len(permutation)):
        perm_list.append(permutation[j])
    return perm_list


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]


@celery.task()
def calculate_mapping(resource_id):
    logger.info("Checking we need to calculating mapping")
    logger.debug(resource_id)

    db = connect_db()
    is_already_calculated, mapping_db_id, result_type = check_mapping_ready(db, resource_id)
    if is_already_calculated:
        logger.info("Mapping '{}' is already computed. Skipping".format(resource_id))
        return

    logger.info("Calculating mapping ")
    # Get the data provider IDS
    dp_ids = list(map(lambda d: d['id'], query_db(db, """
        SELECT id
        FROM dataproviders
        WHERE
          mapping = %s AND uploaded = TRUE
        """, [mapping_db_id])))

    logger.info("Data providers: {}".format(dp_ids))
    assert len(dp_ids) == 2, "Only support two party comparisons at the moment"

    logger.debug("Deserializing filters")
    filters1 = deserialize_filters(get_filter(db, dp_ids[0]))
    filters2 = deserialize_filters(get_filter(db, dp_ids[1]))

    logger.debug("Computing similarity")
    similarity = anonlink.entitymatch.calculate_filter_similarity(filters1, filters2)
    logger.debug("Calculating optimal connections for entire network")
    # The method here makes a big difference in running time
    mapping = anonlink.network_flow.map_entities(similarity,
                                                 threshold=0.95,
                                                 method='bipartite')

    with db.cursor() as cur:
        if result_type == "mapping":
            logger.debug("Saving the blooming data")
            cur.execute("""
                UPDATE mappings SET
                  result = (%s),
                  ready = TRUE,
                  time_completed = now()
                """,
                [psycopg2.extras.Json(mapping)])
        elif result_type == "permutation":
            logger.info("Creating random permutations")

            """
            Pack all the entities that match in the **same** random locations in both permutations.
            Then fill in all the gaps!

            Dictionaries first, then converted to lists.
            """
            smaller_dataset_size = min(len(filters1), len(filters2))
            number_in_common = len(mapping)
            a_permutation = {}  # Should be length of filters1
            b_permutation = {}  # length of filters2

            # By default mark all rows as NOT included in the mask
            mask = {i: False for i in range(smaller_dataset_size)}

            # start with all the possible indexes
            remaining_new_indexes = set(range(smaller_dataset_size))

            logger.info("Randomly assigning indexes for {} matched entities".format(number_in_common))
            for mapping_number, a_index in enumerate(mapping):
                b_index = mapping[a_index]

                # Choose the index in the new mapping (randomly)
                mapping_index = random.choice(tuple(remaining_new_indexes))
                remaining_new_indexes.remove(mapping_index)

                a_permutation[a_index] = mapping_index
                b_permutation[b_index] = mapping_index

                # Mark the row included in the mask
                mask[mapping_index] = True


            logger.info("Randomly adding all non matched entities")

            # Note the a and b datasets could be of different size.
            # At this point, both still have to use the remaining_new_indexes, and any
            # indexes that go over the number_in_common
            remaining_a_values = list(set(range(smaller_dataset_size, len(filters1))).union(remaining_new_indexes))
            remaining_b_values = list(set(range(smaller_dataset_size, len(filters2))).union(remaining_new_indexes))

            # DEBUG ONLY TEST
            a_values = set(a_permutation.values())
            for i in remaining_a_values:
                assert i not in a_values

            # Shuffle the remaining indices on each
            random.shuffle(remaining_a_values)
            random.shuffle(remaining_b_values)

            # For every element in a's permutation
            for a_index in range(len(filters1)):
                # Check if it is not already present
                if a_index not in a_permutation:
                    # This index isn't yet mapped

                    # choose and remove a random index from the extended list of those that remain
                    # note this "could" be the same row (a NOP 1-1 permutation)
                    mapping_index = remaining_a_values.pop()

                    a_permutation[a_index] = mapping_index

            # For every eventual element in a's permutation
            for b_index in range(len(filters2)):
                # Check if it is not already present
                if b_index not in b_permutation:
                    # This index isn't yet mapped

                    # choose and remove a random index from the extended list of those that remain
                    # note this "could" be the same row (a NOP 1-1 permutation)
                    mapping_index = remaining_b_values.pop()
                    b_permutation[b_index] = mapping_index

            logger.info("Completed new permutations for each party")

            for i, permutation in enumerate([a_permutation, b_permutation]):
                perm_list = convert_mapping_to_list(permutation)
                logger.debug("Saving permutations")
                cur.execute("""
                    INSERT INTO permutationdata
                    (dp, raw)
                    VALUES
                    (%s, %s)
                    """,
                    [dp_ids[i], psycopg2.extras.Json(perm_list)]
                )

            logger.info("Encrypting mask data")

            res = query_db(db, """
                SELECT public_key, paillier_context
                FROM mappings
                WHERE
                  resource_id = %s
                """, [resource_id], one=True)
            pk = res['public_key']
            base = res['paillier_context']['base']

            # Subtasks will encrypt the mask in chunks
            logger.info("Chunking mask")
            encrypted_chunks = chunks(convert_mapping_to_list(mask), 1000)
            # calling .apply_async will create a dedicated task so that the
            # individual tasks are applied in a worker instead
            encrypted_mask_future = chord(
                (encrypt_mask.s(chunk, pk, base) for chunk in encrypted_chunks),
                persist_mask.s(dataset_size=smaller_dataset_size,
                               paillier_context=res['paillier_context'])
            ).apply_async()

    # Need to commit the changes we've made
    db.commit()
    logger.info("Mapping saved")
    return 'Done'




@celery.task()
def persist_mask(encrypted_mask_chunks, dataset_size, paillier_context):
    encrypted_mask = [mask for chunk in encrypted_mask_chunks for mask in chunk]
    logger.info("Saving encrypted permutation data to db")
    db = connect_db()
    with db.cursor() as cur:
        cur.execute("""
                    UPDATE mappings SET
                    result = (%s),
                    ready = TRUE,
                    time_completed = now()
                    """,
                [psycopg2.extras.Json(json.dumps({
                    "rows": dataset_size,
                    "mask": encrypted_mask,
                    "paillier_context": paillier_context
                }))])
    db.commit()
    logger.info("Permutation saved (?)")


@celery.task()
def encrypt_mask(values, pk, base):
    logger.info("Encrypting a mask chunk")
    public_key = load_public_key(pk)
    return encrypt_vector(values, public_key, base)


def encrypt_vector(values, public_key, base):
    """
    Encrypt an array of booleans.

    Note the exponent will always be 0

    :return list of encrypted ciphertext strings
    """

    # Only use this for testing purposes!
    # Should use the next section of code instead!
    #return [1 if x else 0 for x in values]

    # Using the default encoding Base:
    return [
        str(public_key.encrypt(int(x)).ciphertext())
        for x in values]


    class EntityEncodedNumber(paillier.EncodedNumber):
        BASE = base
        LOG2_BASE = math.log(BASE, 2)

    encoded_mask = [EntityEncodedNumber.encode(public_key, x) for x in values]

    encrypted_mask = [public_key.encrypt(enc) for enc in encoded_mask]

    return encrypted_mask