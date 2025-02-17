FROM python:3.11

COPY firmRD_src /home/firmRD

RUN pip3 install --no-cache-dir angr==9.0.6885 requests==2.24.0 colorlog==5.0.1 six==1.15.0 lxml==4.9.3 numpy==1.25.0 python-dateutil==2.8.1 protobuf==3.19.0

RUN apt-get update -y && \
    apt-get install -y vim && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /root/.cache && apt-get autoclean && \
    rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/* 

ENV JAVA_HOME /home/firmRD/jdk-17
ENV CLASSPATH $JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar
ENV PATH $PATH:$JAVA_HOME/bin
