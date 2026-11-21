import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from app.core.config import settings

class InMemoryRateLimiter:
    """
    Sliding window in-memory rate limiter for upload and API endpoints.
    Tracks requests per client IP.
    """
    def __init__(self, requests_per_minute: int = 120):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60
        self.history: dict[str, list[float]] = defaultdict(list)

    def check(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        cutoff = now - self.window_seconds

        # Clean old entries
        self.history[client_ip] = [t for t in self.history[client_ip] if t > cutoff]

        if len(self.history[client_ip]) >= self.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait a minute before making more requests."
            )

        self.history[client_ip].append(now)

rate_limiter = InMemoryRateLimiter(settings.RATE_LIMIT_PER_MINUTE)
