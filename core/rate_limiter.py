import threading
import time


class RateLimitExceeded(RuntimeError):
    pass


class RateLimiter:

    def __init__(self, maximum, delay):

        self.maximum = int(maximum)
        self.delay = max(0.0, float(delay))

        self.lock = threading.Lock()

        self.count = 0
        self.last = 0.0

    def wait(self):

        with self.lock:

            if self.count >= self.maximum:
                raise RateLimitExceeded(
                    "Configured HTTP request budget exhausted."
                )

            pause = self.delay - (
                time.monotonic() - self.last
            )

            if pause > 0:
                time.sleep(pause)

            self.last = time.monotonic()
            self.count += 1

    def used(self):
        return self.count
