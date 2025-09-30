from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    print(">>> Home route accessed!")
    return "It works!"

if __name__ == "__main__":
    app.run(debug=True)