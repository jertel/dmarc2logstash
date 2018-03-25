FROM alpine

RUN apk --update upgrade && \
    apk add ca-certificates python2 py2-pip openssl && \
    rm -rf /var/cache/apk/*

COPY src/* /opt/dmarc2logstash/

WORKDIR /opt/dmarc2logstash

ENTRYPOINT ["python", "/opt/dmarc2logstash/dmarc2logstash.py"]