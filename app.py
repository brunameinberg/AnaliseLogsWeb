from flask import Flask, request, render_template, redirect, url_for
from processamento import *
import os
import re
from collections import Counter

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return "Caminho de arquivo inválido", 400
        file = request.files['logfile']
        if file.filename == '':
            return "Nenhum arquivo foi selecionado", 400
        if file:
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            return redirect(url_for('relatorio', filename=file.filename))
        
    return render_template('upload.html')

@app.route('/relatorio/<filename>')
def relatorio(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    dic_ataque_xss, dic_sql_injection, dic_ddos, dic_resposta_positiva_ataque, dic_navegador_suspeito, dic_lfi, dic_directory_transversal, dic_caminhos_suspeitos = processando_dados(file_path)
    return render_template('report.html', dic_ataque_xss=dic_ataque_xss, dic_sql_injection=dic_sql_injection, dic_ddos=dic_ddos, dic_resposta_positiva_ataque=dic_resposta_positiva_ataque, dic_navegador_suspeito=dic_navegador_suspeito, dic_lfi=dic_lfi, dic_directory_transversal=dic_directory_transversal, dic_caminhos_suspeitos=dic_caminhos_suspeitos)


if __name__ == '__main__':
    app.run(debug=True)
