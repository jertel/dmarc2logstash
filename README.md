# DMARC-2-Logstash

Injects POP3-polled DMARC feedback reports into Elasticsearch via Logstash and Filebeat.

## Design

Monitors a given POP3 account for incoming emails and for any attachment it finds, the attachment will analyzed for DMARC XML content. If an eligible attachment, the XML is converted to JSON and written to a dmarc.log file in the current directory (/opt/dmarc2logstash/dmarc.log)If the attachment has a content type of 'application/gzip' or has a .gz or .gzip extension, then the attachment will be gunzipped before analyzing for XML content.

## Elastic Stack (ELK)

For best results, use a filebeat reader and logstash configuration that supports JSON parsing. Examples follow.

### Filebeat Configuration

```
    filebeat.registry_file: /tmp/filebeat_registry
    filebeat.prospectors:
    - type: log
      enabled: true
      paths:
        - "/opt/dmarc2logstash/*.log"
      json.keys_under_root: true
      json.add_error_key: true
      fields_under_root: true
      fields:
        source_type: json-logs
    output.logstash:
      hosts: 
        - logstash:5000
      index: dmarc
      timeout: 15
    logging.level: info
```

### Logstash Configuration

```
    input {
      beats {
        port => 5000
      }
    }

    filter {
      if [source_type] == "json-logs" {
        json { 
          source => "." 
          tag_on_failure => ["_jsonparsefailure"]
        }
      }
      output {
      elasticsearch {
        hosts => ["elasticsearch:9200"]
        index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
      }
    }
```

## Configuration

dmarc2logstash supports two methods of configuration inputs.

1. JSON configuration file
2. Environment variables

Environment variables will take precedence over JSON configuration.

### JSON Configuration

An example configuration file is shown below, followed by descriptions of each setting.

```json
{
  "pop3_server": "outlook.office365.com",
  "pop3_username": "dmarc_feedback@mycompany.invalid",
  "pop3_password": "ThisIsThePassword!",
  "sleep_seconds": 600,
  "json_output_file": "/log/dmarc.json",
  "socket_timeout_seconds": 10,
  "delete_messages": 1,
  "delete_failures": 0
}
```

| variable      | required | description 
|---------------|----------|------------
| pop3_server   | true     | The POP3 server hostname or IP address (must support TLS) 
| pop3_username | true     | POP3 account username
| pop3_password | true     | POP3 account password
| sleep_seconds | false    | Number of seconds to pause in between POP3 mail check; defaults to 300 (5 minutes)
| json_output_file | false | Output file where the JSON records will be written; defaults to dmarc.log in the current working directory.
| socket_timeout_seconds | false | Number of seconds (can be a decimal value) before timing out the POP3 connection. Defaults to 30 seconds.
| delete_messages | true | If set to 1, the messages will be deleted from the inbox after successful parsing. If set to 0, the messages will not be deleted (useful for debugging)
| delete_failures | false | If set to 1, invalid email messages will be deleted from the inbox. If set to 0, the failed messages will not be deleted (useful for debugging)

## Environment Variables

The following environment variables are used as inputs for sensitive information. Environment variables will override any setting defined in the config file.

| variable      | required | description 
|---------------|----------|------------
| POP3_SERVER   | true     | The POP3 server hostname or IP address (must support TLS)
| POP3_USERNAME | true     | POP3 account username
| POP3_PASSWORD | true     | POP3 account password
| POP3_DEBUG_LEVEL | false | Set to 2 for detailed POP3 logging to help diagnose problems with POP3 servers. This variable is only supported through the environment variable, not via the JSON configuration file.
| SLEEP_SECONDS | false    | Number of seconds to pause in between POP3 mail check; defaults to 300 (5 minutes)
| JSON_OUTPUT_FILE | false | Output file where the JSON records will be written; defaults to dmarc.log in the current working directory.
| SOCKET_TIMEOUT_SECONDS | false | Number of seconds (can be a decimal value) before timing out the POP3 connection. Defaults to 30 seconds.
| DELETE_MESSAGES | true | If set to 1, the messages will be deleted from the inbox after successful parsing. If set to 0, the messages will not be deleted (useful for debugging)
| DELETE_FAILURES | false | If set to 1, invalid email messages will be deleted from the inbox. If set to 0, the failed messages will not be deleted (useful for debugging)

## Docker

A Dockerfile is provided for dmarc2logstash, and a Docker image will auto-build at hub.docker.com/jertel/dmarc2logstash.

Ex:

```bash
docker run --rm -v /host/path/logs:/logs -v /host/path/dmarc2logstash.json:/opt/dmarc2logstash/dmarc2logstash.json jertel/dmarc2logstash
```

## Kubernetes

See the Helm chart [README.md](chart/dmarc2logstash/README.md) for information on installing this application into an existing Kubernetes cluster.

## Grafana Dashboard

If you are using Grafana for dashboards, consider importing the included sample [DMARC dashboard](https://github.com/jertel/dmarc2logstash/blob/master/grafana-dashboard.json) into your Grafana installation. This dashboard provides a simple view into the SPM and DKIM pass/fail counts by sending IP and receiving organization.

