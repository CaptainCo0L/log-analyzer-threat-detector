FROM python:3.12-alpine

# tzdata: the 09:00 digest is local time (TZ is set in compose).
# nmap: name discovery's last resort; its connect scan needs no root, so USER stays 1000.
RUN apk add --no-cache tzdata nmap nmap-scripts
# Pillow: the picture cards in Telegram. Fonts come with the code, under data/fonts.
RUN pip install --no-cache-dir Pillow==12.3.0

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY src/ /app/
COPY deploy/hc.sh /hc.sh

USER 1000:1000
ENTRYPOINT ["python", "-m", "pihole_detector"]
CMD ["run"]
