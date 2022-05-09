const express = require ('express')
const bcrypt = require('bcryptjs')  
const jwt = require('jsonwebtoken') 
let apiRouter = express.Router()
const knex = require('knex')({
    client: 'pg',
    debug: true,
    connection: {
        connectionString: process.env.DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        },
    }
}) 

let checkToken = (req, res, next) => { 
    let authToken = req.headers["authorization"] 
    if (!authToken) {         
        res.status(401).json({ message: 'Token de acesso requerida' }) 
    } 
    else { 
        let token = authToken.split(' ')[1] 
        req.token = token 
    } 
 
    jwt.verify(req.token, process.env.SECRET_KEY, (err, decodeToken) => { 
        if (err) { 
            res.status(401).json({ message: 'Acesso negado'}) 
            return 
        } 
        req.usuarioId = decodeToken.id 
        next() 
    }) 
}

let isAdmin = (req, res, next) => { 
    knex 
        .select ('*').from ('usuario').where({ id: req.usuarioId }) 
        .then ((usuarios) => { 
            if (usuarios.length) { 
                let usuario = usuarios[0] 
                let roles = usuario.roles.split(';') 
                let adminRole = roles.find(i => i === 'ADMIN') 
                if (adminRole === 'ADMIN') { 
                    next() 
                    return 
                } 
                else { 
                    res.status(403).json({ message: 'Role de ADMIN requerida' }) 
                    return 
                } 
            } 
        }) 
        .catch (err => { 
            res.status(500).json({  
              message: 'Erro ao verificar roles de usuário - ' + err.message }) 
        }) 
} 
 
apiRouter.get('/produtos', checkToken, (req, res, next) => {
    knex
        .select('*')
        .from('produto')
        .then(produtos => {
            res.status(200).json(produtos);
        })
        .catch(err => res.status(500).json({
            message: 'Erro ao obter lista de produtos: ' + err.message
        }))
})

apiRouter.get('/produtos/:id', checkToken, (req, res, next) => {
    let id = parseInt(req.params.id)
    knex
        .select('*')
        .from('produto')
        .where('id', id)
        .then(produtos => {
            if (produtos.length) {
                res.status(200).json(produtos[0]);
            } else {
                res.status(404).json({
                    message: 'Produto não encontrado'
                })
            }
        })
        .catch(err => res.status(500).json({
            message: 'Erro ao obter lista de produtos: ' + err.message
        }))
})

apiRouter.post('/produtos', checkToken, isAdmin, express.json(), (req, res, next) => {
    knex('produto')
        .insert({
            descricao: req.body.descricao,
            marca: req.body.marca,
            valor: req.body.valor
        }, ['id'])
        .then(resultado => {
            let produto = resultado[0]
            res.status(201).json({
                id: produto.id,
                descricao: req.body.descricao,
                marca: req.body.marca,
                valor: req.body.valor
            })
        })
        .catch (err => {
            res.status(500).json({message: "Erro ao inserir produto" })
        })
})

apiRouter.put('/produtos/:id', checkToken, isAdmin, express.json(), (req, res, next) => {
    let id = parseInt(req.params.id)
    knex('produto')
        .update({
            descricao: req.body.descricao,
            marca: req.body.marca,
            valor: req.body.valor
        })
        .where('id', id)
        .then(resultado => {
            if(resultado !== 0) {
                res.status(200).json('Atualização realizada com sucesso!')
            } else {
                res.status(404).json({
                    message: 'Produto não encontrado'
                })
            }
        })
        .catch(err => res.status(500).json({
            message: 'Erro ao alterar produto: ' + err.message
        }))
})

apiRouter.delete('/produtos/:id', checkToken, isAdmin, express.json(), (req, res, next) => {
    let id = parseInt(req.params.id)
    knex('produto')
        .delete()
        .where('id', id)
        .then(resultado => {
            if(resultado !== 0) {
                res.status(200).json('Deleção realizada com sucesso!')
            } else {
                res.status(404).json({
                    message: 'Produto não encontrado'
                })
            }
        })
        .catch(err => res.status(500).json({
            message: 'Erro ao deletar produto: ' + err.message
        }))
})

apiRouter.post ('/seguranca/register', (req, res) => { 
    knex ('usuario') 
        .insert({ 
            nome: req.body.nome,  
            login: req.body.login,  
            senha: bcrypt.hashSync(req.body.senha, 8),  
            email: req.body.email 
        }, ['id']) 
        .then((result) => { 
            let usuario = result[0] 
            res.status(200).json({"id": usuario.id })  
            return 
        }) 
        .catch(err => { 
            res.status(500).json({  
                message: 'Erro ao registrar usuario - ' + err.message }) 
        })   
}) 

apiRouter.post('/seguranca/login', (req, res) => {  
    knex 
      .select('*').from('usuario').where( { login: req.body.login }) 
      .then( usuarios => { 
          if(usuarios.length){ 
              let usuario = usuarios[0] 
              let checkSenha = bcrypt.compareSync (req.body.senha, usuario.senha) 
              if (checkSenha) { 
                 var tokenJWT = jwt.sign({ id: usuario.id },  
                      process.env.SECRET_KEY, { 
                        expiresIn: 3600 
                      }) 
 
                  res.status(200).json ({ 
                      id: usuario.id, 
                      login: usuario.login,  
                      nome: usuario.nome,  
                      roles: usuario.roles, 
                      token: tokenJWT 
                  })   
                  return  
              } 
          }  
             
          res.status(200).json({ message: 'Login ou senha incorretos' }) 
      }) 
      .catch (err => { 
          res.status(500).json({  
             message: 'Erro ao verificar login - ' + err.message }) 
      }) 
})


 
module.exports = apiRouter; 