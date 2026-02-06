import { useState } from 'react'
import '../css/signup.css'

export const SignUp = ()=>{

    const [form, setForm] = useState({
        username:'',
        password:'',
        email:''
    })

    function handleChange(e){
        setForm({
            ...form,
            [e.target.placeholder]:e.target.value
        })
    }

    function handleSubmit(){
        alert('Submitted')
    }
    return(
        <div className='container'>
        <div className="sign-up">
            <h1>Sign In</h1>
            <form onSubmit={handleSubmit}>
            <input type="text" 
            placeholder='Username' 
            onChange={handleChange}
            value={form.username}
            required/>
            <input type="password" 
            placeholder='Password' 
            onChange={handleChange}
            value={form.password}
            required/>
            <input type="text" 
            placeholder='email' 
            onChange={handleChange}
            value={form.email}
            required/>
            <button type = 'submit'> Submit</button>

            </form>
        </div>

    </div>
    )
}