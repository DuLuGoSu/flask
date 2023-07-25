from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
import bcrypt
import random


app = Flask(__name__)
app.secret_key = 'mysecretkey'

app.jinja_env.add_extension('jinja2.ext.loopcontrols')

# Creamos el filtro datetimeformat y lo registramos en el entorno de Jinja por defecto


def datetimeformat(value):
    return value.strftime('%d-%m-%Y %H:%M')


app.jinja_env.filters['datetimeformat'] = datetimeformat


db = psycopg2.connect(
    host="localhost",
    port=5432,
    user="postgres",
    password="1234",
    database="Traitors"
)


@app.route("/")
def index():
    dia_actual = obtener_dia_actual()
    return render_template("index.html", dia_actual=dia_actual)


@app.route("/login", methods=["GET", "POST"])
def login():
    if 'usuario' in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        nombre_usuario = request.form["nombre_usuario"]
        contrasena = request.form["contrasena"]
        usuario = autenticar_usuario(nombre_usuario, contrasena)
        if usuario:
            session['usuario'] = usuario[0]
            return redirect(url_for("index"))
        else:
            return render_template("login.html", mensaje="Credenciales inválidas")
    else:
        return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if 'usuario' in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        nombre_usuario = request.form["nombre_usuario"]
        contrasena = request.form["contrasena"]

        # Comprobar si el nombre de usuario ya existe
        if nombre_usuario_existe(nombre_usuario):
            return render_template("signup.html", mensaje="El nombre de usuario ya está en uso")

        crear_usuario(nombre_usuario, contrasena)
        return redirect(url_for("login"))
    else:
        return render_template("signup.html")


@app.route("/logout")
def logout():
    session.pop('usuario', None)
    return redirect(url_for("index"))


@app.route("/TRAITORS")
def TRAITORS():

    casas = ['1', '2']
    # Crear una lista de resultados booleanos
    resultados = []
    # Iterar sobre la lista de nombres de casas
    for casa in casas:
        resultado = verificar_casa_llena(casa)
        resultados.append(resultado)

    usuario_inscrito = verificar_inscripcion_casa()
    casa_protegida = False
    if usuario_inscrito > 0:
        casa_protegida = verificar_estado_casa(usuario_inscrito)

    return render_template("traitors.html", tupla_resultados=tuple(resultados),  usuario_inscrito=usuario_inscrito, casa_protegida=casa_protegida, nombres_usuarios=obtener_nombres_usuarios())


@app.route('/conocer_usuarios_en_casa', methods=['GET'])
def conocer_usuarios_en_casa():

    cursor = db.cursor()

    usuario = session['usuario']
    valores_protected = (usuario,)
    consulta_puntos = "UPDATE usuarios SET puntos = puntos - 1 WHERE id = %s"
    cursor.execute(consulta_puntos, valores_protected)

    consulta = "SELECT nombre_usuario FROM usuarios WHERE usuario_casa_inscrito = 1"
    cursor.execute(consulta)
    usuariosCasa1 = cursor.fetchall()

    consulta = "SELECT nombre_usuario FROM usuarios WHERE usuario_casa_inscrito = 2"
    cursor.execute(consulta)
    usuariosCasa2 = cursor.fetchall()

    db.commit()
    cursor.close()

    return render_template('usuariosencasa.html', usuariosCasa1=usuariosCasa1, usuariosCasa2=usuariosCasa2)


def verificar_inscripcion_casa():
    cursor = db.cursor()
    consulta = "SELECT usuario_casa_inscrito FROM usuarios WHERE id = %s"
    usuario = session['usuario']
    valores = (usuario,)
    cursor.execute(consulta, valores)
    resultado = cursor.fetchone()
    cursor.close()
    if resultado is not None:
        return resultado[0]
    else:
        return 0


def verificar_casa_llena(casa):
    cursor = db.cursor()

    # Ejecutar la consulta para obtener el número de la casa especificada y si está protegida
    dia_actual = obtener_dia_actual()
    consulta = f"SELECT casa_{casa} FROM juego WHERE dia = {dia_actual}"
    cursor.execute(consulta)
    result = cursor.fetchone()
    numero_casa = result[0]

    # Verificar si el número es mayor que 3
    if numero_casa and numero_casa > 3:
        return True
    else:
        return False


def verificar_estado_casa(casa):
    cursor = db.cursor()

    # Ejecutar la consulta para obtener el estado de la casa especificada
    dia_actual = obtener_dia_actual()
    consulta = f"SELECT casa_{casa}_protected FROM juego WHERE dia = {dia_actual}"
    cursor.execute(consulta)
    result = cursor.fetchone()
    if result is not None:
        estado_casa = result[0]
        return estado_casa
    else:
        return False


@app.route("/votaciones/<int:id_usuario>")
def votaciones(id_usuario):
    if 'usuario' not in session:
        return redirect(url_for("login"))

    usuario = obtener_usuario_por_id(id_usuario)
    nombres_usuarios = obtener_nombres_usuarios()
    votado = comprobar_votacion_previa()

    # Obtener todas las votaciones de la base de datos, ordenadas por fecha
    votaciones = obtener_votaciones_ordenadas_por_fecha()

    # Preparar los datos para mostrar en la plantilla
    historial = []
    for votacion in votaciones:
        # Obtener los campos relevantes de cada votación
        id_votacion = votacion[0]
        id_jugador_votante = votacion[1]
        id_jugador_votado = votacion[2]
        dia_votado = votacion[3]

        # Obtener los nombres de los jugadores
        votante = obtener_nombre_jugador_por_id(id_jugador_votante)
        candidato = obtener_nombre_jugador_por_id(id_jugador_votado)

        # Agregar los datos a la lista de historial
        historial.append({'id_votacion': id_votacion, 'votante': votante,
                         'candidato': candidato, 'dia': dia_votado})

    return render_template("votaciones.html", usuario=usuario, nombres_usuarios=nombres_usuarios, votado=votado, historial=historial)


def obtener_votaciones_ordenadas_por_fecha():
    cursor = db.cursor()
    consulta = "SELECT * FROM votaciones ORDER BY dia_votado ASC"
    cursor.execute(consulta)
    votaciones = cursor.fetchall()
    cursor.close()
    return votaciones


@app.route("/perfil/<int:id_usuario>")
def perfil_usuario(id_usuario):
    if 'usuario' not in session:
        return redirect(url_for("login"))

    nombreUsuario = obtener_usuario_por_id(id_usuario)
    nombres_usuarios = obtener_nombres_usuarios()
    traidor = obtener_estado_traidor()

    if id_usuario == 27:
        return render_template("admin.html", nombreUsuario=nombreUsuario, nombres_usuarios=nombres_usuarios)
    else:
        return render_template("perfil.html", nombreUsuario=nombreUsuario, nombres_usuarios=nombres_usuarios, traidor=traidor)


def obtener_estado_traidor():
    cursor = db.cursor()
    usuario = session['usuario']
    consulta = "SELECT traitor FROM usuarios WHERE id = %s"
    cursor.execute(consulta, (usuario,))
    resultado = cursor.fetchone()
    cursor.close()
    return resultado


@app.route("/iniciar_juego", methods=["GET", "POST"])
def iniciar_juego():
    if 'usuario' not in session:
        return redirect(url_for("login"))

    # Verificar que el usuario sea el ID 27
    usuario = obtener_usuario_por_id(session['usuario'])
    if usuario[0] != 27:
        return redirect(url_for("index"))

    # Crear las 7 filas en la tabla juego
    cursor = db.cursor()
    consulta = """
        DELETE FROM juego;
        UPDATE dias_juego SET dia_actual = 1;
        UPDATE usuarios SET puntos = 20, traitor = FALSE, protected = FALSE, usuario_casa_inscrito = 0, voto_traidores = 0, traidor_ha_votado = FALSE;
        """
    cursor.execute(consulta)
    db.commit()

    for dia in range(1, 8):
        consulta = "INSERT INTO juego (dia, casa_1, casa_2, casa_1_protected, casa_2_protected, jugador_sentenciado) VALUES (%s, 0, 0, FALSE, FALSE, NULL)"
        valores = (dia,)
        cursor.execute(consulta, valores)
    db.commit()
    cursor.close()

    if request.method == "POST":
        num_traitors = int(request.form["num_traitors"])
        asignar_traitor_a_usuarios(num_traitors)
        return redirect(url_for("index"))

    return redirect(url_for("index"))


def asignar_traitor_a_usuarios(num_traitors):
    cursor = db.cursor()

    # Obtener el número total de jugadores inscritos (excluyendo al usuario administrador)
    consulta_total_jugadores = "SELECT COUNT(*) FROM usuarios WHERE id != 27"
    cursor.execute(consulta_total_jugadores)
    numero_jugadores = cursor.fetchone()[0]

    if numero_jugadores < num_traitors:
        return print(" No hay suficientes jugadores para asignar")

    # Generar números aleatorios distintos para los "traitors"
    numeros_aleatorios = random.sample(
        range(1, numero_jugadores + 1), num_traitors)

    # Asignar el estado de "traitor" a los usuarios correspondientes a los números aleatorios
    consulta_asignar_traitor = "UPDATE usuarios SET traitor = TRUE WHERE id = %s"
    for numero_aleatorio in numeros_aleatorios:
        valores_traitor = (numero_aleatorio,)
        cursor.execute(consulta_asignar_traitor, valores_traitor)

    db.commit()
    cursor.close()


@app.route('/pasar_dia')
def pasar_dia():
    cursor = db.cursor()
    dia_actual = obtener_dia_actual()

    # Contabilizar los votos del día anterior
    jugador_salvado = contabilizar_votos(dia_actual)
    consulta = "UPDATE usuarios SET traitor = FALSE WHERE id = %s"
    cursor.execute(consulta, (jugador_salvado,))

    # Obtener el usuario con el número más alto de voto_traidores
    consulta_max_votos = "SELECT id FROM usuarios ORDER BY voto_traidores DESC LIMIT 1"
    cursor.execute(consulta_max_votos)
    resultado_max_votos = cursor.fetchone()

    if resultado_max_votos:
        id_jugador_traitor = resultado_max_votos[0]

        # Obtener el valor actual de la columna protected del jugador más votado
        consulta_protected = "SELECT protected FROM usuarios WHERE id = %s"
        cursor.execute(consulta_protected, (id_jugador_traitor,))
        protected_jugador_max_votos = cursor.fetchone()[0]

        if not protected_jugador_max_votos:
            # Si protected es False, asignar traitor = True
            consulta_actualizar_traitor = "UPDATE usuarios SET traitor = TRUE WHERE id = %s"
            cursor.execute(consulta_actualizar_traitor, (id_jugador_traitor,))


    # Actualizar la tabla juego con el jugador sentenciado
    consulta = "UPDATE juego SET jugador_sentenciado = %s WHERE dia = %s"
    # valores = (jugador_sentenciado, dia_actual)
    # cursor.execute(consulta, valores)

    # Sumar un número al valor de dia_actual
    nuevo_dia = dia_actual + 1

    # Actualizar el valor de dia_actual en la tabla dias_juego
    consulta = "UPDATE dias_juego SET dia_actual = %s"
    valores = (nuevo_dia,)
    cursor.execute(consulta, valores)
    consulta = "UPDATE usuarios SET protected = FALSE, voto_traidores = 0, traidor_ha_votado = FALSE, usuario_casa_inscrito = 0"
    cursor.execute(consulta)

    db.commit()
    cursor.close()
    return redirect(url_for("index"))


def contabilizar_votos(dia):
    cursor = db.cursor()

    # Contabilizar los votos del día actual
    consulta = "SELECT id_jugador_votado, COUNT(*) AS votos FROM votaciones WHERE dia_votado = %s GROUP BY id_jugador_votado"
    valores = (dia,)
    cursor.execute(consulta, valores)
    votos_por_jugador = cursor.fetchall()

    # Verificar si no hay votos registrados
    if not votos_por_jugador:
        return None

    # Encontrar al jugador sentenciado con más votos
    jugador_salvado = max(votos_por_jugador, key=lambda x: x[1])[0]

    cursor.close()
    return jugador_salvado


def obtener_jugador_sentenciado(dia):
    cursor = db.cursor()

    # Obtener el jugador sentenciado del día anterior
    consulta = "SELECT jugador_sentenciado FROM juego WHERE dia = %s"
    valores = (dia,)
    cursor.execute(consulta, valores)
    jugador_sentenciado = cursor.fetchone()[0]

    cursor.close()
    return jugador_sentenciado


def actualizar_jugador_sentenciado(dia, jugador_sentenciado):
    cursor = db.cursor()

    # Actualizar la tabla juego con el jugador sentenciado del día anterior
    consulta = "UPDATE juego SET jugador_sentenciado = %s WHERE dia = %s"
    valores = (jugador_sentenciado, dia)
    cursor.execute(consulta, valores)

    cursor.close()


@app.route("/inscribirse_en_casa/<int:casa>")
def inscribirse_en_casa(casa):
    if 'usuario' not in session:
        return redirect(url_for("login"))

    id_usuario = session['usuario']
    dia_actual = obtener_dia_actual()

    if verificar_casa_llena(casa):
        return redirect(url_for("TRAITORS"))

    consulta = f"UPDATE juego SET casa_{casa} = casa_{casa} + 1 WHERE dia = {dia_actual}"
    consulta_proteger = "UPDATE usuarios SET usuario_casa_inscrito = %s WHERE id = %s"
    valores_proteger = (casa, id_usuario)

    cursor = db.cursor()
    consulta = f"SELECT casa_{casa}_protected FROM juego WHERE dia = {dia_actual}"
    cursor.execute(consulta)
    resultado = cursor.fetchone()
    if resultado and resultado[0]:
        consulta_proteger_usuario = "UPDATE usuarios SET protected = TRUE WHERE id = %s"
        valores_proteger_usuario = (id_usuario,)
        cursor.execute(consulta_proteger_usuario, valores_proteger_usuario)

    cursor = db.cursor()
    cursor.execute(consulta)
    cursor.execute(consulta_proteger, valores_proteger)
    db.commit()
    cursor.close()

    return redirect(url_for("TRAITORS"))


@app.route('/proteger_casa/<int:casa>')
def proteger_casa(casa):
    if 'usuario' not in session:
        return redirect(url_for("login"))

    cursor = db.cursor()
    usuario = session['usuario']
    valores_protected = (usuario,)

    # Actualizar la columna 'protected' a True para todos los usuarios inscritos en la casa
    consulta_inscritos = "UPDATE usuarios SET protected = TRUE WHERE usuario_casa_inscrito = %s"
    valores_inscritos = (casa,)
    cursor.execute(consulta_inscritos, valores_inscritos)
    db.commit()

    # Descontar 5 puntos al usuario actual

    consulta_puntos = "UPDATE usuarios SET puntos = puntos - 5 WHERE id = %s"
    cursor.execute(consulta_puntos, valores_protected)
    db.commit()

    # Actualizar la tabla juego
    dia_actual = obtener_dia_actual()
    consulta_juego = f"UPDATE juego SET casa_{casa}_protected = TRUE WHERE dia = {dia_actual}"
    cursor.execute(consulta_juego)
    db.commit()

    cursor.close()

    return redirect(url_for("TRAITORS"))


def comprobar_votacion_previa():
    id_jugador_votante = session['usuario']
    dia_votado = obtener_dia_actual()

    cursor = db.cursor()
    # Comprobar votación previa en el mismo día
    consulta_previa = "SELECT * FROM votaciones WHERE id_jugador_votante = %s AND dia_votado = %s"
    valores_previos = (id_jugador_votante, dia_votado)
    cursor.execute(consulta_previa, valores_previos)
    votacion_previa = cursor.fetchone()

    return votacion_previa


@app.route("/votar_jugador", methods=["POST"])
def votar_jugador():
    if 'usuario' not in session:
        return redirect(url_for("login"))

    id_jugador_votante = session['usuario']
    nombre_usuario_votado = request.form["usuarios"]
    id_jugador_votado = obtener_id_usuario(nombre_usuario_votado)
    dia_votado = obtener_dia_actual()
    cursor = db.cursor()

    # Insertar nueva votación
    consulta = "INSERT INTO votaciones (id_jugador_votante, id_jugador_votado, dia_votado) VALUES (%s, %s, %s)"
    valores = (id_jugador_votante, id_jugador_votado, dia_votado)
    cursor.execute(consulta, valores)
    db.commit()
    cursor.close()

    return redirect(url_for("votaciones", id_usuario=id_jugador_votante))


@app.route("/sentenciar_jugador", methods=["POST"])
def sentenciar_jugador():
    if 'usuario' not in session:
        return redirect(url_for("login"))

    usuario_id = session['usuario']
    nombre_usuario_sentenciado = request.form["sentenciar_usuarios"]
    print(nombre_usuario_sentenciado)

    cursor = db.cursor()

    # Actualizar la columna voto_traidores del usuario sumándole uno
    consulta = "UPDATE usuarios SET voto_traidores = voto_traidores + 1 WHERE nombre_usuario = %s"
    cursor.execute(consulta, (nombre_usuario_sentenciado,))
    db.commit()

    # Actualizar la columna traidor_ha_votado a TRUE
    consulta = "UPDATE usuarios SET traidor_ha_votado = TRUE WHERE id = %s"
    cursor.execute(consulta, (usuario_id,))
    db.commit()

    cursor.close()

    return redirect(url_for("chat_traidores"))


@app.route("/chat_traidores")
def chat_traidores():
    # Verificar si el usuario es traidor antes de mostrar el chat
    if 'usuario' in session:
        usuario = obtener_usuario_por_id(session['usuario'])
        if not usuario or not (usuario[4] or usuario[0] == 27):
            return redirect(url_for("index"))

    # Obtener todos los mensajes del chat de la base de datos
    mensajes = obtener_mensajes_chat()
    usuarios_no_traidores = obtener_usuarios_no_traidores()

    # Obtener el valor de traidor_ha_votado del usuario actual
    # Suponiendo que la columna traidor_ha_votado está en la posición 5 de la consulta
    traidor_ha_votado = usuario[8]
    print(traidor_ha_votado)

    return render_template("chat_traidores.html", mensajes=mensajes, usuarios_no_traidores=usuarios_no_traidores, traidor_ha_votado=traidor_ha_votado)


@app.route('/enviar_mensaje', methods=['POST'])
def enviar_mensaje():
    if 'usuario' not in session:
        return redirect(url_for("login"))

    mensaje = request.form['mensaje']
    guardar_mensaje(mensaje)

    return redirect(url_for('chat_traidores'))


def guardar_mensaje(mensaje):
    cursor = db.cursor()
    consulta = "INSERT INTO chat (mensaje, fecha_envio) VALUES (%s, NOW())"
    valores = (mensaje,)
    cursor.execute(consulta, valores)
    db.commit()
    cursor.close()


def obtener_mensajes_chat():
    cursor = db.cursor()
    consulta = "SELECT mensaje, fecha_envio FROM chat ORDER BY fecha_envio DESC"
    cursor.execute(consulta)
    mensajes = cursor.fetchall()
    cursor.close()
    return mensajes


def obtener_usuarios_no_traidores():
    # Realizar la conexión a la base de datos
    cursor = db.cursor()

    # Consultar los usuarios que no son traidores
    consulta = "SELECT nombre_usuario FROM usuarios WHERE traitor = FALSE;"
    cursor.execute(consulta)
    usuarios_no_traidores = [usuario[0] for usuario in cursor.fetchall()]
    cursor.close()
    print(usuarios_no_traidores)
    return usuarios_no_traidores


def obtener_id_usuario(nombre_usuario):
    cursor = db.cursor()
    consulta = "SELECT id FROM usuarios WHERE nombre_usuario = %s"
    valores = (nombre_usuario,)
    cursor.execute(consulta, valores)
    resultado = cursor.fetchone()
    cursor.close()

    if resultado:
        return resultado[0]
    else:
        return None


def obtener_dia_actual():
    cursor = db.cursor()
    consulta = "SELECT dia_actual FROM dias_juego LIMIT 1"
    cursor.execute(consulta)
    dia_actual = cursor.fetchone()[0]
    cursor.close()
    return dia_actual


def obtener_nombres_usuarios():
    cursor = db.cursor()
    consulta = "SELECT nombre_usuario FROM usuarios"
    cursor.execute(consulta)
    nombres_usuarios = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return nombres_usuarios


def obtener_usuario_por_id(id_usuario):
    cursor = db.cursor()
    consulta = "SELECT * FROM usuarios WHERE id = %s"
    valores = (id_usuario,)
    cursor.execute(consulta, valores)
    usuario = cursor.fetchone()
    cursor.close()
    return usuario


def obtener_nombre_jugador_por_id(id_usuario):
    cursor = db.cursor()
    consulta = "SELECT nombre_usuario FROM usuarios WHERE id = %s"
    valores = (id_usuario,)
    cursor.execute(consulta, valores)
    usuario = cursor.fetchone()
    cursor.close()

    if usuario:
        nombre_usuario = usuario[0]
        return nombre_usuario
    else:
        return None


def autenticar_usuario(nombre_usuario, contrasena):
    contrasena = contrasena.encode('utf-8')
    cursor = db.cursor()
    consulta = "SELECT * FROM usuarios WHERE nombre_usuario = %s"
    valores = (nombre_usuario,)
    cursor.execute(consulta, valores)
    usuario = cursor.fetchone()
    cursor.close()
    if usuario and bcrypt.checkpw(contrasena, usuario[2].encode('utf-8')):
        return usuario
    return None


def crear_usuario(nombre_usuario, contrasena):
    contrasena = contrasena.encode('utf-8')
    contrasena_hashed = bcrypt.hashpw(contrasena, bcrypt.gensalt())
    cursor = db.cursor()
    consulta = "INSERT INTO usuarios (nombre_usuario, contrasena, protected, usuario_casa_inscrito) VALUES (%s, %s, false, 0)"
    valores = (nombre_usuario, contrasena_hashed.decode('utf-8'))
    cursor.execute(consulta, valores)
    db.commit()
    cursor.close()


def nombre_usuario_existe(nombre_usuario):
    cursor = db.cursor()
    consulta = "SELECT COUNT(*) FROM usuarios WHERE nombre_usuario = %s"
    valores = (nombre_usuario,)
    cursor.execute(consulta, valores)
    count = cursor.fetchone()[0]
    cursor.close()
    return count > 0


if __name__ == "__main__":
    app.run(debug=True)
