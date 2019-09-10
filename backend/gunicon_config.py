from prometheus_client import multiprocess


# gunicorn config for metrics to work across multiple processes
def child_exit(server, worker):
    multiprocess.mark_process_dead(worker.pid)
