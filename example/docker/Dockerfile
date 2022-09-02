FROM ubuntu:22.10

RUN apt update && apt install curl xz-utils -y

RUN curl -sS https://raw.githubusercontent.com/rusty-ferris-club/shellclear/main/install/install.sh | sh

RUN ln -sf /bin/bash /bin/sh

RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=~/.bash_history" \
    && echo "$SNIPPET" >> "/root/.bashrc"

RUN echo 'GITHUB_TOKEN=catch-me' > /root/.bash_history

RUN echo 'eval $(shellclear --init-shell)' >> ~/.bashrc
