import UserModel from '../model/User.model.js' // if we write only "../model/User.model" this, then it will throw error 
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import ENV from '../config.js'
import otpGenerator from 'otp-generator'

// middleware for verify user */
export async function verifyUser(req, res, next){
    try{

        const { username } = req.method == "GET" ? req.query : req.body
        
        // check the user existance
        let exist = await UserModel.findOne({ username })
        if(!exist) return res.status(404).send({ error : "Cant find User!" })
        next()

    } catch(error){
        return res.status(404).send({ error : "Authentication Error" });
    }
}



export async function register(req, res){
    // res.json('register route is here. check it')



    //** Code by Youtube Tutor */
    try{
        const { username, password, profile, email } = req.body;
        
        // check the existing user
        const existUsername = new Promise((resolve, reject) => {
            UserModel.findOne({ username }).then((user) => {
                // if(err) reject(new Error(err))
                if(user) reject({ error: "Please use unique username"});

                resolve();
            }).catch(err => reject({error: "exist username findone error"}));
        });


        // check for existing email
        const existEmail = new Promise((resolve, reject) => {
            UserModel.findOne({ email }).then((err, email) => {
                if(err) reject(err)
                if(email) reject({ error: "Please use unique email"});

                resolve();
            }).catch(err => reject({error: "exist username findone error"}));
        });
        

        Promise.all([existUsername, existEmail])
            .then(() => {
                if(password){
                    bcrypt.hash(password, 10)
                        .then( hashedPassword => {

                            const user = new UserModel({
                                username,
                                password: hashedPassword,
                                profile: profile || '',
                                email
                            });

                            // return save result as a response
                            user.save()
                                .then(result => res.status(201).send( { msg: "User register successful", result}))
                                .catch(error => res.status(500).send({error: "This error is here in inner catch block"}))


                        }).catch(error => {
                            return res.status(500).send({
                                error: "Enable to hashed password"
                            })
                        })
                }
            }).catch(error => {
                return res.status(500).send({error: "username or email already in use"});
            })
        
    } catch(error){
        return res.status(500).send({error: "guys, error is in outermost catch block"})
    }






    // //** My Own personal code in place of code above */
    // const { username, password, profile, email } = req.body 
    // const user = new UserModel({
    //     username,
    //     password,
    //     profile,
    //     email
    // })
    // user.save()
    //     .then(result => res.status(201).send(result + {msg: "User register successful"}))
    //     .catch(error => res.status(500).send({error: "This error is here in inner catch block"}))
    
}



export async function login(req, res){
    // res.json('login route is here. check it')

    const { username, password } = req.body

    try{

        UserModel.findOne({ username })
            .then(user => {
                bcrypt.compare(password, user.password)
                    .then(passwordCheck => {

                        if(!passwordCheck) return res.status(400).send({ error: "Dont have password"})

                        //create jwt token
                        const token = jwt.sign({
                                        userId: user._id,
                                        username: user.username
                                    }, ENV.JWT_SECRET , { expiresIn: "24h" })
                        
                        return res.status(200).send({
                            msg: "Login successful...!",
                            username: user.username,
                            token
                        })

                    })
                    .catch(error => {
                        return res.status(400).send({ error: "Password does not match" })
                    })
            })
            .catch(error => {
                return res.status(404).send({error: "Username not found"})
            })

    } catch(error){
        return res.status(500).send({error: "This is catch error of login route"})
    }
}



export async function getUser(req, res){
    // res.json('getUser route is here. check it')

    const { username } = req.params

    try{

        if(!username) return res.status(501).send({error: "Invalid Username"})

        UserModel.findOne({ username }).then(( user ) => {
            // if(error) return res.status(500).send({errorMessage: "Here is error no. 2", error: error})
            if(!user) return res.status(501).send({ error: "Couldnt find the user" })

            const { password, ...rest } = Object.assign({}, user.toJSON())

            return res.status(201).send(rest)
        }).catch(error => {
            return res.send({
                error: "error in findOne of getUser route"
            })
        })

    } catch(error){
        return res.status(404).send({error: "Cannot find user data"})
    }

}



export async function generateOTP(req, res){
    // res.json('generateOTP route is here. check it')

    // OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    res.status(201).send({ code: req.app.locals.OTP })    
}



export async function verifyOTP(req, res){
    // res.json('verifyOTP route is here. check it')

    const { code } = req.query;
    if(parseInt(req.app.locals.OTP) === parseInt(code)){
        req.app.locals.OTP = null; // reset the OTP value
        req.app.locals.resetSession = true; // start session for reset password
        return res.status(201).send({ msg: 'Verify Successsfully!'})
    }
    return res.status(400).send({ error: "Invalid OTP"});
}



export async function createResetSession(req, res){
    // res.json('createResetSession route is here. check it')

    if(req.app.locals.resetSession){
        // req.app.locals.resetSession = false //allow access to this route only once
        // return res.status(201).send({ msg : "access granted!"})
        return res.status(201).send({ flag : req.app.locals.resetSession})
   }
   return res.status(440).send({error : "Session expired!"})
}



// res.json('updateUser route is here. check it')
export async function updateuser(req, res){

    try{

        // const id = req.query.id
        const { userId } = req.user;

        if(userId){
            const body = req.body

            // update the data
            UserModel.updateOne({ _id : userId }, body).then(data => {
                
                return res.status(201).send({ msg: "Record Updated...!" })
            }).catch(error => {
                return res.send({
                    error: "error in findOne of updateuser route"
                })
            })

        }else{
            return res.status(401).send({ error: "User not found"})
        }

    } catch(error){
        return res.status(401).send({ error })
    }

}


export async function resetPassword(req, res){
    // res.json('resetPassword route is here. check it')

    try {
        
        if(!req.app.locals.resetSession) return res.status(440).send({error : "Session expired!"});

        const { username, password } = req.body;

        try {
            
            UserModel.findOne({ username})
                .then(user => {
                    bcrypt.hash(password, 10)
                        .then(hashedPassword => {
                            UserModel.updateOne({ username : user.username },
                            { password: hashedPassword}).then(data => {
                                req.app.locals.resetSession = false; // reset session
                                return res.status(201).send({ msg : "Record Updated...!"})
                            }).catch(error => {
                                return res.send({
                                    error: "error in findOne of updateuser route"
                                })
                            })
                        })
                        .catch( e => {
                            return res.status(500).send({
                                error : "Enable to hashed password"
                            })
                        })
                })
                .catch(error => {
                    return res.status(404).send({ error : "Username not Found"});
                })

        } catch (error) {
            return res.status(500).send({ error })
        }

    } catch (error) {
        return res.status(401).send({ error })
    }
}
