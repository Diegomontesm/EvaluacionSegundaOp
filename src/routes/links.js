const express=require('express');
const router=express.Router();

const pool = require('../database');

//LLAMAMOS METODO PARA PROTEGER LINKS
const {isLoggedIn} = require('../lib/auth');

router.get('/add', (req, res)=>{
    res.render('links/add');
});

router.post('/add', async (req,res )=>{
    const {title, url, description} = req.body;
    const newLink ={
        title,
        url,
        description,
        user_id: req.user.id
    };
    await pool.query('INSERT INTO links SET ?', [newLink]);
    console.log(newLink);
    req.flash('success','El link se ha guardado');
    res.redirect('/links');
});

router.get('/', isLoggedIn, async(req, res)=>{
    const links = await pool.query('SELECT * FROM links WHERE user_id=?', [req.user.id]);    
    console.log(links)
    res.render('links/list', {links:links});
});

router.get('/delete/:id', isLoggedIn,async (req, res )=>{
    const {id} = req.params;
    await pool.query('DELETE FROM links WHERE ID = ?', [id]);
    req.flash('success','El link se ha borrado');
    res.redirect('/links');
})

router.get('/edit/:id', isLoggedIn,async (req, res )=>{
    const {id} = req.params;
    const links = await pool.query('SELECT * FROM links WHERE ID = ?', [id]);    
    res.render('links/edit', {links: links[0]});
})

router.post('/edit/:id', isLoggedIn,async (req,res)=>{
    const{id} = req.params;
    const{title,description,url}= req.body;
    const newLink ={
        title,
        description,
        url
    };    
    await pool.query('UPDATE links SET ? WHERE ID = ?', [newLink, id]);
    req.flash('success','El link se ha actualizado');
    res.redirect('/links');
});




module.exports=router;