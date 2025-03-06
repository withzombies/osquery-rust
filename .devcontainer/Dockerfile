FROM rust:1.85-bullseye

# Install curl
RUN apt update \
    && apt install -y \
    curl \
    git \
    software-properties-common \
    vim \
    jq

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B \
    && add-apt-repository 'deb [arch=arm64] https://pkg.osquery.io/deb deb main'

# Install osquery
RUN apt update -y && apt install -y osquery

# Configure osquery, enable FIM
RUN cat /opt/osquery/share/osquery/osquery.example.conf | sed -r 's/.*\/\/.*//g' | jq '.options.disable_events = "false" | \
                                                                                       .options.enable_file_events = "true" | \
                                                                                       .file_paths.critical_files = ["/etc/%%", "/var/www/%%", "/home/%/.ssh/%%", "/tmp/%%"] | \
                                                                                       .exclude_paths.critical_files = ["/var/www/cache/%%", "/tmp/sessions/%%"] | \
                                                                                       .schedule.fim_query.query = "SELECT * FROM file_events;" | \
                                                                                       .schedule.fim_query.interval = 300' > /etc/osquery/osquery.conf

RUN osqueryctl start osquery

# Install additional tools
RUN rustup component add rustfmt clippy

WORKDIR /workspace

CMD ["bash"]