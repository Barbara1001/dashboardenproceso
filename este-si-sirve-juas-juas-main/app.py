from flask import Flask, render_template,request,redirect, url_for,flash, session #importa de Flask
app =Flask(__name__) #inicializa o instancia
app.secret_key = "clave_secreta"
from flask_mysqldb import MySQL 
import MySQLdb.cursors

from werkzeug.security import generate_password_hash , check_password_hash#importa las funciones de seguridad para encriptar la contraseña

import secrets
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
 
app.config['MYSQL_HOST']= 'localhost' #servidor de base de datos
app.config['MYSQL_USER']= 'root'#usuario por defecto
app.config['MYSQL_PASSWORD']= ''
app.config['MYSQL_DB']= 'sapja'

mysql=MySQL(app) #inicializa la conexion a la base de datos

def generate_token(email):
    token = secrets.token_urlsafe(32) # Genera un token seguro
    expiry = datetime.now() + timedelta(hours=1) 
    cur = mysql.connection.cursor()
    cur.execute("UPDATE usuarios SET reset_token = %s, token_expiry = %s WHERE correo = %s", (token, expiry, email))
    mysql.connection.commit()
    cur.close()
    return token

def enviar_correo_resete(email, token):
    enlace = url_for('reset', token=token, _external=True)
    cuerpo=(f"""Para restablecer su contraseña, haga clic en el siguiente enlace:
            {enlace}
            Si no solicitó este cambio, ignore este correo electrónico.
            Este enlace es válido por 1 hora""")
    remitente = 'elotakuquelevalevergatodo@gmail.com'
    clave = 'vbpd adre bres hxcc'
    mensaje = MIMEText(cuerpo)
    mensaje['Subject'] = 'Restablecimiento de contraseña'
    mensaje['From'] = 'elotakuquelevalevergatodo@gmail.com'
    mensaje['To'] = email

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(remitente, clave)
    server.sendmail(remitente, email, mensaje.as_string())
    server.quit()

@app.route("/") #se define la ruta 
def index(): #funcion
    return render_template("index.html") #usamos render_template para mostrar el archivo html(en este caso el index.html)

@app.route('/login', methods=['GET', 'POST']) #ruta para el login, acepta metodos GET y POST
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_ingresada = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT  id_usuario ,nombres,password FROM usuarios WHERE correo = %s", (username,))
        usuario = cur.fetchone()
        cur.close()

        if usuario and check_password_hash(usuario[2], password_ingresada):
            session['usuario'] = usuario[1]  # Guarda el nombre del usuario en la sesión
            flash(f"Bienvenido, {usuario[1]}!")
            return redirect(url_for('dashboard'))
        else:
            flash("Usuario o contraseña incorrectos")
    return render_template('login.html')

@app.route('/logout') #ruta para el logout
def logout():
    session.clear()  # Limpia la sesión
    flash("Has cerrado sesión exitosamente")
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST']) #ruta para el registro, acepta metodos GET y POST
def registro():
    if request.method == 'POST':
        nombres = request.form['nombres']
        apellidos = request.form['apellidos']
        correo = request.form['correo']
        password = request.form['password']
        hash = generate_password_hash(password)

        cur = mysql.connection.cursor() #crea un cursor para ejecutar consultas
        try:
            cur.execute("""INSERT INTO usuarios (nombres, apellidos, correo, password) VALUES (%s, %s, %s, %s)""", (nombres, apellidos, correo, hash))
            mysql.connection.commit() #confirma los cambios en la base de datos
            flash ("su usuario ha sido registrado exitosamente")
            return redirect(url_for('login'))
        except:
            flash("este corrreo ya esta registrado")
        finally:
            cur.close()
            
            
    return render_template('registro.html')

@app.route ('/olvidarc', methods=['GET', 'POST']) #ruta para olvidar la contraseña, acepta metodos GET y POST
def olvidarc():
    if request.method == 'POST':
        email = request.form['email']
        cur = mysql.connection.cursor()
        cur.execute("SELECT id_usuario FROM usuarios WHERE correo= %s", (email,))
        existe = cur.fetchone()
        cur.close()
       

        if not existe:
            flash("El correo electrónico no está registrado")
            return redirect(url_for('olvidarc'))
        
        token = generate_token(email)
        enviar_correo_resete(email, token)
        flash("Se ha enviado un enlace de restablecimiento de contraseña a su correo electrónico")
        return redirect(url_for('login'))
    return render_template('olvidarc.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id_usuario, token_expiry FROM usuarios WHERE reset_token = %s", (token,))
    usuario = cur.fetchone()
    cur.close()

    if not usuario or datetime.now() > usuario[1]:
        flash("El enlace de restablecimiento de contraseña es inválido o ha expirado")
        return redirect(url_for('olvidarc'))

    if request.method == 'POST':
        nueva_password = request.form.get('nueva_password')
        if not nueva_password:
            flash("Debes ingresar la nueva contraseña")
            return render_template('reiniciar.html', token=token)
        hash_nueva_password = generate_password_hash(nueva_password)

        cur = mysql.connection.cursor()
        cur.execute("UPDATE usuarios SET password = %s, reset_token = NULL, token_expiry = NULL WHERE id_usuario = %s", (hash_nueva_password, usuario[0]))
        mysql.connection.commit()
        cur.close()

        flash("Su contraseña ha sido restablecida exitosamente")
        return redirect(url_for('login'))

    return render_template('reiniciar.html', token=token)

@app.route('/dashboard') #ruta para el dashboard
def dashboard():
    if 'usuario' not in session:
        flash("Por favor, inicia sesión para acceder al dashboard")
        return redirect(url_for('login'))
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id_usuario, nombres, apellidos, correo FROM usuarios")
    usuarios = cursor.fetchall()    
    cursor.close()
    return render_template('dashboard.html', usuarios=usuarios)


if __name__ =="__main__": #verifica si el archivo se ejecuta directamente

    app.run(port=5000,debug=True) #permite ver errores detalladamente y recarga e servidor automaticamente cunado se hacen cambios

