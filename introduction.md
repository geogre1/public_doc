[ELK Stack](https://www.elastic.co/cn/elastic-stack)

---

![beats][beats]
## Beats
Beats 是一个面向轻量型采集器的平台，这些采集器可从边缘机器发送数据。

---

![logstash][logstash]
## Logstash
Logstash 是动态数据收集管道，拥有可扩展的插件生态系统。

---

![elasticsearch][elasticsearch]
## ElasticSearch
Elasticsearch 是一个基于 JSON 的分布式搜索和分析引擎。

---

![kibana][kibana]
## Kibana
Kibana 可以让您的数据变得有形有样，是一个可扩展的用户界面。

---

<br>
<br>
<br>
<br>



# filebeat
filebeat是一个比较常用的[beat类型][beat-types],它是一个轻量型日志采集器。[doc][filebeat-doc]

### filebeat的输入
```yml
filebeat.inputs:
  # filebeat可以有多个输入
  - type: log 
    # Use the log input to read lines from log files.
    enabled: true 
    # 输入开关
    tags: ["django", "cr"]
    # 数据源的标签，一般的可以用于最终数据的分类筛选、logstash的处理器的选择
    paths: 
    # 监控日志文件的路径，可以有多个
      - /var/log/beats/log.log 
      # 也可以用通配符 - /logs/*.log
    multiline:
      pattern: ^(CRITICAL|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|NOTSET)\s
      # 正则
      negate: true
      # 正则选中的一行是独立的一条日志(true)还是一条其他日志的附属(false)
      match: after
      # 被判定不是独立的日志的行是追加到上一条(after)还是等待下一条并附在前面(before)
```
### filebeat的输出

Beats can send data directly to Elasticsearch or via Logstash, where you can further process and enhance the data, before visualizing it in Kibana.

![data-flow][data-flow]

输出到logstash
```yml
output.logstash:
  hosts: [ "localhost:5044" ]
```
或者输出到elasticsearch(不使用logstash处理或者filebeat直接使用预制模板处理)
```yml
output.elasticsearch:
 hosts: [ "localhost:9200" ]
```

以上即为一个简单的filebeat.yml配置文件，docker运行时映射到`/usr/share/filebeat/filebeat.yml`即可

# logstash
logstash是处理数据的管道 [doc][logstash-doc]

```python
input {
   beats {
     port => 5044 # 监听端口号
   }
}

filter {
    if "spring" in [tags] { # 使用tag作为选择使用处理器的条件
        grok {
            match => { "message" => '(?<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \d{,3})' }
            # 使用正则把字符串字段拆成多个字段，不符合正则则不处理
        }
        date {
            match => [ "time", "yyyy-MM-dd HH:mm:ss SSS"]
            # 把指定字段转为时间格式后赋给@timestamp字段，作为这条日志的标准时间
            timezone => "Asia/Shanghai"
            # 注意指定时区，不宜修改kibana的时区
        }
    }
}

output {
    elasticsearch { # 输出es
       hosts => ["http://172.29.100.168:9200"]
       index => "filebeat-%{+YYYY.MM.dd}" # 指定输出到es的index
    }
}
```
执行命令`logstash -f ./logstash.conf`

---

或者也可以把conf文件拆开写
```
/etc/logstash/conf.d/
- 02-beats-input.conf  
- 10-syslog.conf  
- 11-nginx.conf  
- 30-output.conf
```

02-beats-input.conf
```
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-beats.crt"
    ssl_key => "/etc/pki/tls/private/logstash-beats.key"
  }
}
```
10-syslog.conf
```
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
```
11-nginx.conf
```
filter {
  if [type] == "nginx-access" {
    grok {
      match => { "message" => "%{NGINXACCESS}" }
    }
  }
}
```
30-output.conf
```
output {
  elasticsearch {
    hosts => ["localhost"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
  }
}
```
数据(event)会按照文件名的字母顺序依次通过这些管道

重新加载logstash config `kill -SIGHUP ${pid}`

# kibana

Kibana 是一个免费且开放的用户界面，能够让您对 Elasticsearch 数据进行可视化，并让您在 Elastic Stack 中进行导航。您可以进行各种操作，从跟踪查询负载，到理解请求如何流经您的整个应用，都能轻松完成。[doc][kibana-doc] [docker][kibana-docker]

## Index patterns

在`/app/management/kibana/indexPatterns`管理index parttens

如"filebeat-*"，选择该index partten时，es中所有的以"filebeat-"开头的索引都会被匹配到

index patten 的 "Available fields"是固定的，即使数据源中发生了变化，需要同步这一变化，需在index partten管理页"Refresh field list"

## Search

在`/app/discover`查看es中的原始数据并管理"search"

创建search时可以指定日志列表所显示的字段，根据fields和时间做条件筛选

创建好的search可以用于visualization可视化图表，也可以直接插入dashboard


## visualize

在`/app/visualize`管理

使用一个search或者直接使用一个index partten作为数据源，作出一个可视化模块，比如饼图、直方图、仪表盘。

## dashboard

在`/app/dashboards`管理

visualization和search的组合





[elasticsearch]: https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt850b5bd506c6b3ce/5d0cfe28d8ff351753cbf2ad/logo-elastic-search-color-64.svg
[kibana]: https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt38b131256d241912/5d0cfe3a970556dd5800ebfe/logo-kibana-64-color.svg
[beats]: https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt4da03cec7fcabcac/5d0cfe4b77f34fd55839b480/logo-beats-64-color.svg
[logstash]: https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt8d79255492e03260/5d0cfe54561b9b0b537f94e8/logo-logstash-64-color.svg
[data-flow]: https://www.elastic.co/guide/en/beats/libbeat/current/images/beats-platform.png

[beat-types]: https://www.elastic.co/guide/en/beats/libbeat/current/beats-reference.html
[filebeat-doc]: https://www.elastic.co/guide/en/beats/filebeat/current/index.html
[logstash-doc]: https://www.elastic.co/guide/en/logstash/current/index.html
[kibana-doc]: https://www.elastic.co/cn/kibana/features
[kibana-docker]: https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-docker.html