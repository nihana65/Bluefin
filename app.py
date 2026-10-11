from fastapi import FastAPI
from pydantic import BaseModel
from Fintech import inspect

app = FastAPI(title="BankSim: Blue-Team AI Firewall")


class Req(BaseModel):
    input: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/inspect")
def inspect_endpoint(req: Req):
    return inspect(req.input)
