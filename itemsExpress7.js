const express = require('express');
const mysql = require('mysql2');
var passwordValidator = require('password-validator');
var emailValidator = require('email-validator');
const { v4: uuidv4 } = require('uuid');
const { response } = require('express');
const cors = require('cors');
const app = express();
const port = 3002;

const connection = mysql.createConnection({
    host: '165.22.14.77',
    user: 'b27',
    password: 'b27',
    database: 'dbSrinivas'
  });

app.use(cors());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

let validateMiddlewareForToken = (request, response, next) => {
    const token = request.headers.authorization;
    const path = request.path;
    const authenticationNotRequired = {"login": "/api/login", "signup": "/api/signup"};
    if(path == authenticationNotRequired.login || path == authenticationNotRequired.signup) {
        next();
    }
    else {
        if(token == null || token == undefined) {
            response.status(401).send({ "Error": "User is unauthorized!" });
        }
        else {
            request["token"] = token;
            next();
        }
    }
}

let validateUserFromDatabase = (request, response, next) => {
    const query = "select userId from users where token = ?";
    const values = [request.token];
    if(values[0] == undefined) {
        next();
    }
    else {
        connection.promise().execute(query, values)
        .then((rows) => {
            const result = rows[0];
            if(result.length == 0) {
                response.status(401).send({"Messsage": "User is unauthorized!"});
            }
            else {
                request["userId"] = result[0]["userId"];
                next();
            }
        })
        .catch((error) => {
            console.log(error);
            response.status(500).send({"Error": "Internal server error!"});
        });
    }
}

app.use(validateMiddlewareForToken);
app.use(validateUserFromDatabase);

app.post("/api/signup", (request, response) => {
    const username = request.body.username;
    const password = request.body.password;
    const errors = {};
    validateUser(username, password, response, () => {
        if(emailValidator.validate(username)) {
            let schema = new passwordValidator;
            schema
            .is().min(6)
            .has().symbols(1)
            .has().not().spaces()
            if(schema.validate(password)) {
                const token = uuidv4();
                const query = "insert into users values(default, ?, ?, ?)";
                const values = [username, password, token];
                connection.promise().execute(query, values)
                .then((rows) => {
                    const result = rows[0];
                    const userId = result.insertId;
                    response.status(201).send({"userId": userId});
                });
            }
            else {
                const conditions = "Your password must contain atleast one special character and no white spaces!";
                errors["password"] = conditions;
                response.status(400).send(errors);
            }
        }
        else {
            errors["username"] = "Please enter a valid username!";
            response.status(400).send(errors);
        }
    });
});

app.post("/api/login", (request, response) => {
    const username = request.body.username;
    const password = request.body.password;
    validateUser(username, password, response, () => {
        const query = "select userId from users where username = ?";
        connection.promise().execute(query, [username])
        .then((rows) => {
            const result = rows[0];
            if(result.length != 0) {
                const query = "select token, username from users where username = ? and password = ?";
                const values = [username, password];
                connection.promise().execute(query, values)
                .then((rows) => {
                    const result = rows[0];
                    if(result.length == 0) {
                        response.status(404).send({"Error": "Invalid Password!"});
                    }
                    else {
                        response.status(200).send(result);
                    }
                });
            }
            else {
                response.status(404).send({"Error": "User not found!"});
            }
        })
        .catch((error) => {
            console.log(error);
            response.status(500).send({"Error": "Internal server error!"});
        });
    });
});

app.get("/api/course/", (request, response) => {
    const query = "select itemId, title, description from items where userId = ? and status = 1";
    const values = [request.userId];
    connection.promise().execute(query, values)
    .then((rows) => {
        const result = rows[0];
        if(result.length != 0) {
            response.status(200).send(result);
        }
        else {
            response.status(200).send({"Error": "Data not found!"});
        }
    })
    .catch((error) => {
        console.log(error);
        response.status(500).send({"Error": "Internal server error!"});
    });
});

app.post("/api/course/", (request, response) => {
    const errors = {};
    const userId = request.userId;
    const values = [request.body.title, request.body.description, userId];
    if(values[0] == undefined || values[1] == undefined) {
        if(values[0] == undefined) {
            errors["title"] = "Please enter title!";
        }
        if(values[1] == undefined) {
            errors["description"] = "Please enter description!";
        }
        response.status(400).send(errors);
    }
    else {
        const query = "insert into items(title, description, status, userId) values (?, ?, 1, ?)";
        connection.promise().execute(query, values) 
        .then((rows) => {
            result = rows[0];
            response.status(201);
            connection.promise().query(`select itemId, title, description from items where itemId = ${result["insertId"]}`)
            .then((rows) => {
                const result = rows[0];
                response.json(result);
            });
        })
        .catch((error) => {
            console.log(error);
            response.status(500).send({"Error": "Internal server error!"});
        });
    }
});

app.put("/api/course/:pk", (request, response) => {
    const userId = request.userId;
    const id = request.params.pk;
    const values = [request.body.title, request.body.description, id];
    searchItem(userId, id, response, () => {
        const query = "update items set title = ?, description = ? where itemId = ?";
        connection.promise().execute(query, values) 
        .then((rows) => {
            const result = rows[0];
            const affectedRows = result["affectedRows"];
            if(affectedRows != 0) {
                response.status(200);
                const selectQuery = "select itemId, title, description from items where itemId = ?";
                connection.promise().execute(selectQuery, [id])
                .then((rows) => {
                    const result = rows[0];
                    response.send(result);
                });
            }
        })
        .catch((error) => {
            console.log(error);
            response.status(500).send({"Error": "Internal server error!"});
        });
    });
});

app.delete("/api/course/:pk", (request, response) => {
	const userId = request.userId;
	const id = request.params.pk;
	searchItem(userId, id, response, () => {
		const updateQuery = `update items set status = 0 where itemId = ?`;
		connection.promise().execute(updateQuery, [id])
		.then((rows) => {
			const result = rows[0];
			const affectedRows = result["affectedRows"];
			if(affectedRows != 0) {
				response.status(200).send({"Message": "Deleted successfully!"});
			}
		})
		.catch((error) => {
			console.log(error);
			response.status(500).send({"Error": "Internal server error."});
		});
	});
});

app.get('/api/course/:pk', (request, response) => {
	const userId = request.userId;
	const id = request.params.pk;
	searchItem(userId, id, response, () => {
		const selectQuery = `select itemId, title, description from items where itemId = ?`;
		connection.promise().execute(selectQuery, [id])
		.then((rows) => {
			const result = rows[0];
			if (result.length != 0) 
			{
				response.status(200).send(result);
			}
		})
		.catch((error) => {
			console.log(error);
			response.status(500).send({"Error": "Internal server error!"});
		});
	});
});

let searchItem = (userId, syllabusId, response, callback) => {
	const searchQuery = "select userId from items where itemId = ? and status = 1";
	connection.promise().execute(searchQuery, [syllabusId])
	.then((rows) => {
		const result = rows[0];
		if (result.length != 0) 
		{
			const resultUserId = result[0]["userId"];
			if(resultUserId != userId)
			{
				response.status(403).send({"Message": "You have no access."});
			}
			else
			{
				callback();
			}
		}
		else
		{
			response.status(404).send({ "Message": "Syllabus not found." });
		}
	})
	.catch((error) => {
		console.log(error);
		response.status(500).send({"Message": "Internal server error."});
	});
}

let validateUser = (username, password, response, callback) => {
    let errors = {};
    if(username == undefined || password == undefined) {
        if(username == undefined) {
            errors["username"] = "Please enter username!";
        }
        if(password == undefined) {
            errors["password"] = "Please enter password!";
        }
        response.status(400).send(errors);
    }
    else {
        callback();
    }
}

app.listen(port, () => {
    console.log(`App listening http://localhost:${port}`);
});