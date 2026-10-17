# Code Art Analyzer

Ferramenta desenvolvida em Python com interface gráfica para monitoramento de conectividade, visualização de gráficos e acompanhamento de alertas de ping.

## Requisitos

- Python 3
- Tkinter
- CustomTkinter
- Pillow
- Matplotlib

## Instalação no Kali Linux

Atualize os pacotes e instale as dependências do sistema:

```bash
sudo apt update
sudo apt install python3-tk python3-pil python3-pil.imagetk python3-venv -y
```

Entre na pasta do projeto e crie um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instale as bibliotecas Python:

```bash
python -m pip install customtkinter pillow matplotlib
```

## Executar

```bash
python ping.py
```

## Tecnologias utilizadas

- Python
- CustomTkinter
- Tkinter
- Pillow
- Matplotlib

As bibliotecas são utilizadas para construir a interface gráfica, manipular imagens e apresentar gráficos de monitoramento.
