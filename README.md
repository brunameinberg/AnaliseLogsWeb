# Analisador de Logs Web

O **Analisador de Logs Web** é uma ferramenta para análise de logs de acesso a servidores. Ele identifica possíveis ameaças e atividades suspeitas com base em padrões conhecidos de ataques. A ferramenta processa arquivos de log no formato Apache/Nginx e fornece um relatório detalhado das detecções realizadas.

## 🚀 Funcionalidades

- **Detecção de Ataques XSS**: Identifica scripts maliciosos e atividades relacionadas.
- **Detecção de Injeções SQL**: Localiza possíveis tentativas de explorar vulnerabilidades de banco de dados.
- **Detecção de Ataques DDoS**: Monitora requisições de alta frequência de um mesmo IP.
- **Detecção de Respostas Positivas a Ataques**: Verifica mudanças no tamanho da resposta para requisições iguais.
- **Navegadores Suspeitos**: Analisa o agente do usuário para identificar navegadores desconhecidos ou maliciosos.
- **Directory Transversal e LFI**: Detecta tentativas de acessar arquivos confidenciais ou explorar falhas locais.
- **Caminhos Suspeitos**: Identifica acessos a caminhos críticos como `/admin`, `/login` ou arquivos de configuração sensíveis.
- **Estatísticas Detalhadas**: Gera estatísticas com os IPs mais ativos em cada tipo de ataque.

## 🛠️ Tecnologias Utilizadas

- **Python**: Linguagem de programação principal.
- **Coleções e DefaultDict**: Para organização eficiente dos dados.
- **Regex**: Para correspondência de padrões nos logs.
- **Datetime**: Para manipulação de datas e detecção de intervalos.

## 📂 Estrutura do Projeto

```plaintext
project/
│
├── app.py                     # Arquivo principal da aplicação
├── processamento.py           # Lógica de processamento dos logs e detecção de ataques
├── templates/
│   ├── upload.html            # Página inicial para upload de logs
│   ├── report.html            # Relatório gerado após análise
├── static/
│   ├── styles.css             # Estilos CSS
│   ├── styleupload.css        # Estilos CSS
│   ├── script.js              # Scripts adicionais (opcional)
├── README.md                  # Documentação do projeto
```

## ⚙️ Como Funciona

1. O usuário faz upload de um arquivo de log no formato `.log`.
2. O sistema lê e processa o arquivo, convertendo as linhas em dicionários organizados.
3. São aplicados diferentes padrões e técnicas para detectar:
   - **Scripts maliciosos** (`<script>`, `onload=`, etc.).
   - **Consultas SQL suspeitas** (`SELECT`, `' OR '1'='1`, etc.).
   - **Requisições de alta frequência** para identificar ataques DDoS.
   - **Acessos a caminhos críticos** como `/admin` ou arquivos `.env`.
4. O relatório final apresenta as ameaças detectadas, incluindo:
   - **IPs envolvidos**.
   - **Descrições detalhadas dos ataques**.
   - **Datas e requisições relacionadas**.

## 📋 Pré-requisitos

- **Python 3.8 ou superior**.
- Dependências: `pip install -r requirements.txt`

## 🖥️ Execução Local

1. Clone este repositório:

   ```bash
   git clone https://github.com/brunameinberg/AnaliseLogsWeb.git
   cd AnaliseLogsWeb
   ```
2. Execute o script principal
   
   ```bash
   python app.py
   ```
   
3. Acesse a aplicação em seu navegador
   
   ```plaintext
   http://localhost:5000
   ```

4. Faça upload de um arquivo .log e analise os resultados!

## 👨‍💻 Contribuidores

- Bruna Lima Meinberg
- Luana Wilner Abramoff


