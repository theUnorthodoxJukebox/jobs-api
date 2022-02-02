const jwt=require('jsonwebtoken')
const {BadRequest}=require('../errors')

const login = async(req, res)=>
{
    const {username, password}=req.body

    if(!username || !password)
    {
        throw new BadRequest('Please enter username and password')
    }
    
    const id = new Date().getDate()

    const token = jwt.sign({id, username}, process.env.JWT_SECRET, {expiresIn: '30d'})

    res.status(200).json({msg: 'User created', token})
}

const dashboard = async(req, res)=>
{

    console.log(req.user);

    res.status(200).json( {msg: `hello ${req.user.username}`})


    
}


module.exports = 
{
    login,
    dashboard
}