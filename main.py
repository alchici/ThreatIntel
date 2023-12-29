from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from test import getTactics, getTechniques, getSubtechniques, getGroups
from rules import createRules
from latex import process
import shutil
import os
from fastapi.responses import FileResponse, RedirectResponse
app = FastAPI()

# uvicorn main:app --reload

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class form(BaseModel): 
    title: str | None = None
    author: str | None = None
    description: str | None = None
    groups: list | None = None
    subtechniques: list | None = None
    iocs: list | None = None

@app.get("/my-first-api")
def hello(name: str):
  return {'Hello ' + name + '!'} 

@app.get("/tactics")
def tactics():
  result = getTactics()
  return result

@app.get("/techniques/{tactic}")
def techniques(tactic):
  result = getTechniques(tactic)
  return result

@app.get("/subtechniques/{tactic}/{technique}")
def subtechniques(tactic, technique):
  result = getSubtechniques(tactic, technique)
  return result

@app.get("/groups")
def groups():
  result = getGroups()
  return result

@app.post("/submit")
def submit(data: form):
  print(data)
  createRules(data)
  process(data)
  return RedirectResponse("/report", status_code=status.HTTP_302_FOUND)

@app.get("/report")
def report():
  # headers = {
  #       "Content-Disposition": "attachment; filename=report.pdf"
  #   }  

  # response = FileResponse("./generated/main.pdf", media_type="application/pdf", headers=headers)
  # return response
  os.system("rm -r result")
  os.system("mkdir result")
  os.system("cp -r generated result/operational")
  os.system("cp -r rules result/tactic")
  shutil.make_archive('result', 'zip', 'result')

  headers = {
        "Content-Disposition": "attachment; filename=result.zip"
    }  

  response = FileResponse("./result.zip", media_type="application/zip", headers=headers)
  return response
