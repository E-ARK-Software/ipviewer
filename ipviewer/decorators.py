import json
import os

from eatb.utils.datetime import ts_date

from functools import wraps

from config.configuration import task_logfile_name
from ipviewer.util import TaskLog


def task_logger(f):
    @wraps(f)
    def wrapper(*args, **kwds):
        user_path = args[0]
        user_id = args[1]
        task_log = TaskLog(os.path.join(user_path, task_logfile_name))
        try:
            kwds["task_log"] = task_log
            result = f(*args, **kwds)
        except Exception as ex:
            msg = "Exception {0}".format(ex)
            task_log.log(msg)
            print(msg)
            raise ex
        finally:
            task_log.close()
        return result
    return wrapper



