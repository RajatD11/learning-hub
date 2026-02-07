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
            [e.target.name]:e.target.value
        })
    }

    function handleSubmit(e){
        e.preventDefault();
        console.log('Form data:', form)
    }
    return(
        <div className='container'>
        <div className="sign-up">
            <h1>Sign In</h1>
            <form onSubmit={handleSubmit}>
            <input type="text" 
            name='username'
            placeholder='Username' 
            onChange={handleChange}
            value={form.username}
            required/>
            <input type="password" 
            placeholder='Password' 
            name='password'
            onChange={handleChange}
            value={form.password}
            required/>
            <input type="text" 
            placeholder='email' 
            name='email'
            onChange={handleChange}
            value={form.email}
            required/>
            <button type = 'submit'> Submit</button>

            </form>
        </div>

    </div>
    )
}