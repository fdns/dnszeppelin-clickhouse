FROM ubuntu:16.04

RUN apt-get update \
  && apt-get install -y wget libfontconfig \
  && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/fdns/grafana/releases/download/v4.5.2-clickhouse/grafana_4.5.2-1506619414_amd64.deb &&\
    dpkg -i grafana*.deb &&\
    rm grafana*.deb &&\
    mkdir -p /usr/share/grafana

# Install plugins
RUN grafana-cli --pluginsDir "/usr/share/grafana/data/plugins" plugins install grafana-piechart-panel

EXPOSE 3000
CMD ["grafana-server", "-homepath", "/usr/share/grafana"]