FROM python:3.12-alpine

# tzdata: the 09:00 digest is local time (TZ is set in compose).
RUN apk add --no-cache tzdata

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY src/ /app/
COPY deploy/hc.sh /hc.sh

USER 1000:1000
ENTRYPOINT ["python", "-m", "pihole_detector"]
CMD ["run"]
