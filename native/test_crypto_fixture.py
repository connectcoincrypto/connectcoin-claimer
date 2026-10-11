"""Offline native parser/RSA bounds/chain policy differential regression corpus."""
from __future__ import annotations
import argparse
import dataclasses
import json
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers/tests"))
from test_verifier_security import certificate, signed_proof, verify_fixture
from test_rsa_exponent_limits import _rsa_certificate, _certificate_message, _ec_identity, _proof
from cryptography.hazmat.primitives import serialization

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args=parser.parse_args()
    requests=[]
    expected=[]
    def verify(envelope, root, valid, name):
        context=dataclasses.asdict(envelope)
        proof=context.pop("proof")
        requests.append({"mode":"verify", "context":context,"proof":proof.hex(),"roots":root.public_bytes(serialization.Encoding.PEM).decode()})
        expected.append((valid,name))
    root=certificate(401,"Native test root",ca=True)
    leaf=certificate(402,"Native test leaf",issuer=root,dns_name="example.com")
    good=signed_proof("example.com",leaf,[])
    verify_fixture(good,root[1])
    verify(good,root[1],True,"valid EC proof")
    for time in (1,253402300799): verify(dataclasses.replace(good,validation_time=time),root[1],False,"changed validation time")
    verify(dataclasses.replace(good,signature_algorithms_mask=2),root[1],False,"disallowed signature")
    verify(dataclasses.replace(good,input_index=1),root[1],False,"wrong claim challenge")
    verify(dataclasses.replace(good,connection_work_target="00"*32),root[1],True,"valid work miss")
    unrelated=certificate(403,"Unrelated root",ca=True)
    verify(good,unrelated[1],False,"untrusted root")
    duplicate=signed_proof("example.com",leaf,[root[1]]*7)
    verify(duplicate,root[1],True,"trusted duplicate issuers")
    verify(duplicate,unrelated[1],False,"untrusted duplicate issuers bounded")
    # Every truncation of a signed proof must fail, including partial DER/CV.
    for size in range(len(good.proof)):
        verify(dataclasses.replace(good,proof=good.proof[:size]),root[1],False,f"truncated {size}")
    for position in (0,1,2,5,8,len(good.proof)-1):
        changed=bytearray(good.proof);changed[position]^=1
        verify(dataclasses.replace(good,proof=bytes(changed)),root[1],False,f"tampered {position}")
    ecroot,ecleaf=_ec_identity()
    for pss in (False,True):
        for exponent in (65537,(1<<63)+1,(1<<64)+1):
            cert=_rsa_certificate(exponent,pss=pss)
            message=_certificate_message([ecleaf,cert])
            requests.append({"mode":"certificate","proof":message.hex()})
            expected.append((exponent.bit_length()<=64,f"RSA exponent {exponent.bit_length()} PSS {pss}"))
            if exponent.bit_length()>64:
                verify(_proof([ecleaf,cert]),ecroot,False,"unused RSA exponent bound")
    result=subprocess.run([args.binary],input="".join(json.dumps(x)+"\n" for x in requests),text=True,capture_output=True,timeout=45)
    if result.returncode: raise AssertionError(result.stderr)
    results=[json.loads(x) for x in result.stdout.splitlines()]
    assert len(results)==len(expected),(len(results),len(expected),result.stderr)
    for value,(valid,name) in zip(results,expected):
        assert value["valid"]==valid,(name,value)
        if name=="valid work miss": assert value["meets_target"] is False
    print(f"{len(expected)} native crypto fixture cases passed")
if __name__=="__main__": main()
