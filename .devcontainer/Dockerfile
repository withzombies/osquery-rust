FROM rust:1.85-bullseye

# Install curl
RUN apt update \
    && apt install -y \
    curl \
    git \
    software-properties-common \
    vim

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B \
    && add-apt-repository 'deb [arch=arm64] https://pkg.osquery.io/deb deb main'

# Install osquery
RUN apt update -y && apt install -y osquery

RUN cp /opt/osquery/share/osquery/osquery.example.conf /etc/osquery/osquery.conf
RUN osqueryctl start osquery

# Install additional tools
RUN rustup component add rustfmt clippy

WORKDIR /workspace

CMD ["bash"]