FROM ubuntu:22.04

RUN apt-get update -y && apt-get upgrade -y

RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata

RUN apt-get install -y python3 pip libcairo2 texlive-latex-base texlive-fonts-recommended texlive-fonts-extra texlive-latex-extra texlive-bibtex-extra

COPY . /app

WORKDIR /app

RUN pip install uvicorn fastapi mitreattack-python pydantic cairosvg 

ENTRYPOINT [ "/bin/bash", "./run.sh"]