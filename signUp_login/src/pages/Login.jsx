import '../css/login.css'

export const Login = () =>{
    function handleSubmit(e){
        e.preventDefault();
    }
    return (
        <div className='container'>
            <div className='login'>
                <div> 
                    <h1>Tanya Ka Dil</h1>
                    <form onSubmit={handleSubmit}>
                        <input 
                            type='text'
                            name='username'
                            placeholder="Username or Email"
                            required
                        />
                        <input 
                            type='password'
                            name='password'
                            placeholder="Password"
                            required
                        />
                        <button type='submit'>Submit</button>
                    </form>
                </div>  {/* Close wrapper div */}
            </div>
        </div>
    )
}