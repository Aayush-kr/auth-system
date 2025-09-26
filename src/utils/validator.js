const {z}  = require('zod');


const validateRegister = z.object({
    name: z.string().min(3, 'Name must be 3 character long'),
    email: z.email({ pattern: z.regexes.email }),
    password: z.string().min(6, 'Password must be atleast 6 character long')
})

const validateLogin = z.object({
    email: z.email({ pattern: z.regexes.email }),
    password: z.string().min(6, 'Password must be atleast 6 character long')
})





const getAllErrors = (validation) => {
    const errors = validation.error;
    let errorMsg = 'Validation Error';
    let allErrors = [];

    if(errors?.issues && Array.isArray(errors.issues)) {
        allErrors = errors.issues.map(issue => ({
            field: issue.path ? issue.path.join('.') : 'unknown',
            message: issue.message || errorMsg,
            code: issue.code
        }))
        errorMsg = allErrors[0]?.message || 'Validation Error';
    }
    return {errorMsg, allErrors}
}

module.exports  = {validateRegister,getAllErrors,validateLogin}