const express = require('express');
const mysql = require('mysql');
const util = require('util');
const jwt = require('jsonwebtoken');
const unless = require('express-unless');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());

const PORT = process.env.PORT ? process.env.PORT : 3000;

const conexion = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'diplomatura',
});
conexion.connect();
const query = util.promisify(conexion.query).bind(conexion);

const auth = (req, res, next) => {
  try {
    let token = req.headers['authorization'];

    if (!token) {
      throw new Error('No estas logueado');
    }

    token = token.replace('Bearer ', '');

    jwt.verify(token, 'Secret', (err, user) => {
      if (err) {
        throw new Error('Token invalido');
      }
    });

    next();
  } catch (e) {
    res.status(403).send({ message: e.message });
  }
};

auth.unless = unless;

app.use(
  auth.unless({
    path: [
      { url: '/login', methods: ['POST'] },
      { url: '/registro', methods: ['POST'] },
    ],
  }),
);

app.post('/registro', async (req, res) => {
  try {
    if (!req.body.usuario || !req.body.clave || !req.body.email) {
      throw new Error('No enviaste todos los datos necesarios');
    }
    const validacionUsuario = await query('select * from usuario where usuario=?', [req.body.usuario]);
    if (validacionUsuario.length > 0) {
      throw new Error('El usuario ya existe');
    }

    //Si esta todo bien, encripto la clave
    const claveEncriptada = await bcrypt.hash(req.body.clave, 10);

    // Guardar el usuario con la clave encriptada
    const usuario = {
      usuario: req.body.usuario,
      clave: claveEncriptada,
      email: req.body.email,
    };
    // @todo save
    // await query("insert into usuario (usuario, clave, email) values (?,?,?)", [req.body.usuario, claveEncriptada, req.body.email])
    await query('insert into usuario (usuario, clave, email) values (?,?,?)', [
      usuario.usuario,
      usuario.clave,
      usuario.email,
    ]);

    res.send({ message: 'Se registro correctamente' });
  } catch (e) {
    res.status(413).send({ message: e.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    if (!req.body.usuario || !req.body.clave) {
      throw new Error('No enviaste los datos necesarios');
    }

    // @todo fetch user
    const usuario = await query('select * from usuario where usuario=?', [req.body.usuario]);
    if (usuario.length == 0) {
      throw new Error('Usuario/Password incorrecto');
    }
    const claveCoincide = bcrypt.compareSync(req.body.clave, usuario[0].clave);

    if (!claveCoincide) {
      throw new Error('Usuario/Password incorrecto');
    }

    // Paso 1: encuentro el usuario en la base de datos
    // select * from usuario where usuario = req.body.usuario
    // usuario.find({usuario: req.body.usuario})
    // si no lo encontras -> error
    //const claveEncriptada = "fdfadsfds";

    // Paso 2: verificar la clave
    //if(!bcrypt.compareSync(req.body.clave, claveEncriptada)){
    //    throw new Error("Fallo el login");
    //}

    // Paso 3: sesion
    const tokenData = {
      usuario: usuario[0].usuario,
      email: usuario[0].email,
      user_id: usuario[0].id,
    };

    const token = jwt.sign(tokenData, 'Secret', {
      expiresIn: 60 * 60 * 24, // expires in 24 hours
    });

    res.send({ token });
  } catch (e) {
    res.status(413).send({ message: e.message });
  }
});

app.get('/api/personas', async (req, res) => {
  const respuesta = await query('select id, nombre, apellido, edad from persona');
  // for (let i = 0; i < respuesta.length; i++) {
  //   respuesta[i].numeroOrden = i+1;
  // }
  // respuesta.forEach((elemento, idx) => {
  //   elemento.numeroOrden = idx;
  // });
  res.json(respuesta);
});

app.get('/api/personas/:id', async (req, res) => {
  try {
    const respuesta = await query('select * from persona where id=?', [req.params.id]);
    if (respuesta.length == 1) {
      res.json(respuesta[0]);
    } else {
      res.status(404).send();
    }
  } catch (e) {
    res.send('La persona no existe');
  }
});

app.post('/api/personas', async (req, res) => {
  try {
    const nombre = req.body.nombre;
    const apellido = req.body.apellido;
    const edad = req.body.edad;
    const salario = req.body.salario;
    const respuesta = await query('insert into persona (nombre, apellido, edad, salario) values (?, ?, ?, ?)', [
      nombre,
      apellido,
      edad,
      salario,
    ]);
    // respuesta.insertId
    const registroInsertado = await query('select * from persona where id=?', [respuesta.insertId]);
    res.json(registroInsertado[0]);
  } catch (e) {
    res.status(500).send('Error en la operacion');
  }
});

app.put('/api/personas/:id', async (req, res) => {
  try {
    const nombre = req.body.nombre;
    const apellido = req.body.apellido;
    const edad = req.body.edad;
    const salario = req.body.salario;
    const respuesta = await query('update persona set nombre=?, apellido=?, edad=?, salario=? where id=?', [
      nombre,
      apellido,
      edad,
      salario,
      req.params.id,
    ]);
    const registroInsertado = await query('select * from persona where id=?', [req.params.id]);
    res.json(registroInsertado[0]);
  } catch (e) {
    res.status(500).send('Error en la operacion');
  }
});

app.delete('/api/personas/:id', async (req, res) => {
  try {
    const registro = await query('select * from persona where id=?', [req.params.id]);
    if (registro.length == 1) {
      await query('delete from persona where id=?', [req.params.id]);
      res.status(204).send();
    } else {
      res.status(404).send();
    }
  } catch (e) {
    res.status(500).send('Error en la operacion');
  }
});

app.listen(PORT, () => {
  console.log('App corriendo en el puerto ' + PORT);
});

// recurso: personas

// Listar *
//  GET /personas

// Obtener un elemento particular *
// GET /personas/8

// Agregar
// POST /personas
// los datos de la persona en formato JSON

// Modificar
// PUT /personas/9
// los datos de la persona en formato JSON

// Borrar
// DELETE /personas/10
