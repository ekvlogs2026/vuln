from flask import Flask, request, render_template_string

app = Flask(__name__)

HOME = """
<h1>Vulnerable Flask Lab</h1>

<h2>1. SSTI Demo</h2>
<form action="/ssti">
  <input name="name" placeholder="Try: {{7*7}}">
  <button>Submit</button>
</form>

<h2>2. Reflected XSS Demo</h2>
<form action="/xss">
  <input name="q" placeholder='Try: <script>alert(1)</script>'>
  <button>Submit</button>
</form>
"""

@app.route("/")
def home():
    return HOME

@app.route("/ssti")
def ssti():
    name = request.args.get("name", "")
    template = f"""
    <h1>Hello {name}</h1>
    <a href="/">Back</a>
    """
    return render_template_string(template)

@app.route("/xss")
def xss():
    q = request.args.get("q", "")
    return f"""
    <h1>Search results for:</h1>
    <p>{q}</p>
    <a href="/">Back</a>
    """

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
