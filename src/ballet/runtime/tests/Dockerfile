FROM python:3.8-buster

RUN apt-get install bash

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install solana

# docker run -v .:/tests --security-opt label=disable python3.8 python3 /tests/gen_c_tests.py
