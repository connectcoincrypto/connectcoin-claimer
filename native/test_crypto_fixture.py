"""Offline native parser/RSA bounds/chain policy differential regression corpus."""
from __future__ import annotations
import argparse
import dataclasses
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "helpers/tests"))
from test_verifier_security import certificate, signed_proof, verify_fixture
from test_rsa_exponent_limits import _rsa_certificate, _certificate_message, _ec_identity, _proof
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

def reissue(cert, issuer_key, *, padding=0, serial=None, extensions=None, valid_from=None, valid_to=None):
    """Keep the exact public key/name/policy but produce deliberately new DER."""
    builder=(x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
             .public_key(cert.public_key()).serial_number(serial or cert.serial_number)
             .not_valid_before(valid_from or cert.not_valid_before_utc).not_valid_after(valid_to or cert.not_valid_after_utc))
    for ext in cert.extensions:
        value=(extensions or {}).get(ext.oid, ext.value)
        builder=builder.add_extension(value, ext.critical)
    if padding:
        builder=builder.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"x"*padding), False)
    return builder.sign(issuer_key, hashes.SHA256())

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args=parser.parse_args()
    requests=[]
    expected=[]
    def verify(envelope, root, valid, name, *, clear=False, prepared=False):
        context=dataclasses.asdict(envelope)
        proof=context.pop("proof")
        requests.append({"mode":"verify", "context":context,"proof":proof.hex(),"roots":root.public_bytes(serialization.Encoding.PEM).decode()})
        if clear: requests[-1]["clear_cache"]=True
        if prepared: requests[-1]["prepared"]=True
        expected.append((valid,name))
        return len(requests)-1
    root=certificate(401,"Native test root",ca=True)
    leaf=certificate(402,"Native test leaf",issuer=root,dns_name="example.com")
    good=signed_proof("example.com",leaf,[])
    reference=verify_fixture(good,root[1])
    cold=verify(good,root[1],True,"valid EC proof",clear=True)
    warm=verify(good,root[1],True,"cached valid EC proof")
    dates=[]
    valid_from=int(leaf[1].not_valid_before_utc.timestamp())
    valid_to=int(leaf[1].not_valid_after_utc.timestamp())
    for time,valid in ((valid_from-1,False),(valid_from,True),(valid_to,True),(valid_to+1,False),(good.validation_time,True)):
        dates.append(verify(dataclasses.replace(good,validation_time=time),root[1],valid,"cached date boundary"))
    for time in (1,253402300799): verify(dataclasses.replace(good,validation_time=time),root[1],False,"changed validation time")
    verify(dataclasses.replace(good,signature_algorithms_mask=2),root[1],False,"disallowed signature")
    verify(dataclasses.replace(good,input_index=1),root[1],False,"wrong claim challenge")
    verify(dataclasses.replace(good,root_certificates_version=2),root[1],False,"wrong root policy")
    verify(dataclasses.replace(good,connection_work_target="00"*32),root[1],True,"valid work miss")
    verify(signed_proof("other.example",leaf,[]),root[1],False,"cached key wrong hostname")
    changed_cv=bytearray(good.proof);changed_cv[-1]^=1
    invalid_cv=verify(dataclasses.replace(good,proof=bytes(changed_cv)),root[1],False,"cached key invalid CV")
    same_name_root=certificate(403,"Native test root",ca=True)
    verify(good,same_name_root[1],False,"same root DN different key")
    same_key_root=reissue(root[1],root[0],serial=1401)
    before_parent=verify(good,root[1],True,"original parent before DER change")
    changed_parent=verify(good,same_key_root,True,"same parent key changed DER")
    changed_parent_hit=verify(good,same_key_root,True,"changed parent warmed")
    bad_der=bytearray(leaf[1].public_bytes(serialization.Encoding.DER));bad_der[-1]^=1
    corrupt_leaf=(leaf[0],x509.load_der_x509_certificate(bytes(bad_der)))
    bad_child=signed_proof("example.com",corrupt_leaf,[])
    child_bad1=verify(bad_child,root[1],False,"changed child DER invalid signature")
    child_bad2=verify(bad_child,root[1],False,"negative signature not memoized")
    verify(good,root[1],True,"negative result cannot poison good edge")
    unrelated=certificate(403,"Unrelated root",ca=True)
    verify(good,unrelated[1],False,"untrusted root")
    duplicate=signed_proof("example.com",leaf,[root[1]]*7)
    verify(duplicate,root[1],True,"trusted duplicate issuers")
    verify(duplicate,unrelated[1],False,"untrusted duplicate issuers bounded")
    # Exact-DER metadata must change with KU/EKU or validity, even with the same
    # subject/key. An unused supplied certificate still constrains validity.
    before_usage=verify(good,root[1],True,"metadata before policy changes",clear=True)
    no_sign=x509.KeyUsage(False,False,False,False,False,False,False,None,None)
    ku_bad=(leaf[0],reissue(leaf[1],root[0],extensions={x509.ExtensionOID.KEY_USAGE:no_sign}))
    ku_first=verify(signed_proof("example.com",ku_bad,[]),root[1],False,"changed DER invalid KU")
    ku_again=verify(signed_proof("example.com",ku_bad,[]),root[1],False,"cached invalid KU remains rejected")
    client_only=x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH])
    eku_bad=(leaf[0],reissue(leaf[1],root[0],extensions={x509.ExtensionOID.EXTENDED_KEY_USAGE:client_only}))
    verify(signed_proof("example.com",eku_bad,[]),root[1],False,"changed DER invalid EKU")
    expired=(leaf[0],reissue(leaf[1],root[0],valid_to=datetime(2026,1,1,tzinfo=UTC)))
    verify(signed_proof("example.com",expired,[]),root[1],False,"changed DER expired validity")
    early=(leaf[0],reissue(leaf[1],root[0],valid_from=datetime(1960,1,1,tzinfo=UTC)))
    verify(signed_proof("example.com",early,[]),root[1],False,"invalid Unix date conversion stays rejected")
    unused=certificate(450,"Unused expired certificate",ca=True)
    unused_expired=reissue(unused[1],unused[0],valid_to=datetime(2026,1,1,tzinfo=UTC))
    verify(signed_proof("example.com",leaf,[unused_expired]),root[1],False,"unused expired certificate")
    metadata_restored=verify(good,root[1],True,"metadata after rejected different DER")
    # Per-bounty/static context reuse changes the supplied time, not its range
    # or certificate checks; changed static inputs must force full preparation.
    reuse_cold=verify(good,root[1],True,"prepared context cold",clear=True,prepared=True)
    reuse_time=verify(dataclasses.replace(good,validation_time=good.validation_time+1),root[1],True,"prepared new time",prepared=True)
    reuse_expired=verify(dataclasses.replace(good,validation_time=1),root[1],False,"prepared expired time",prepared=True)
    for invalid_time in (0,253402300800):
        index=verify(good,root[1],False,"prepared invalid time boundary",prepared=True)
        requests[index]["context"]["validation_time"]=invalid_time
    reuse_restored=verify(good,root[1],True,"prepared restored time",prepared=True)
    reuse_target=verify(dataclasses.replace(good,connection_work_target="00"*32),root[1],True,"valid work miss",prepared=True)
    reuse_mask=verify(dataclasses.replace(good,signature_algorithms_mask=2),root[1],False,"prepared changed mask",prepared=True)
    reuse_domain=verify(signed_proof("other.example",leaf,[]),root[1],False,"prepared changed hostname",prepared=True)
    verify(dataclasses.replace(good,txid="02"*32),root[1],False,"prepared changed transaction",prepared=True)
    verify(dataclasses.replace(good,input_index=1),root[1],False,"prepared changed input",prepared=True)
    # Exact-message LRU: A,A,B,A parses only twice. A hit must refresh recency,
    # and subsequent eviction must not invalidate a copied/moved CapturedProof.
    alternating=[good]+[signed_proof("example.com",certificate(serial,"LRU leaf",issuer=root,dns_name="example.com"),[])
                        for serial in range(460,464)]
    lru_a=verify(good,root[1],True,"LRU A cold",clear=True)
    requests[lru_a]["hold"]=True
    lru_aa=verify(good,root[1],True,"LRU A warm")
    lru_b=verify(alternating[1],root[1],True,"LRU B cold")
    lru_aba=verify(good,root[1],True,"LRU A after B")
    for envelope in alternating[2:4]: verify(envelope,root[1],True,"LRU fill")
    lru_full=verify(alternating[4],root[1],True,"LRU evict B")
    lru_a_kept=verify(good,root[1],True,"LRU recently used A retained")
    lru_b_evicted=verify(alternating[1],root[1],True,"LRU B must reparse")
    # A malformed DER message never enters the cache or displaces warm A.
    malformed=bytearray(_certificate_message([leaf[1]])); malformed[11]=0x31
    malformed_cases=[]
    for _ in range(2):
        malformed_cases.append(len(requests))
        requests.append({"mode":"certificate","proof":malformed.hex()})
        expected.append((False,"malformed message cannot poison LRU"))
    malformed_restored=verify(good,root[1],True,"warm A after malformed DER")
    parallel=verify(good,root[1],True,"parallel LRU isolation")
    requests[parallel].update(parallel=True,alternate_proof=alternating[1].proof.hex())
    # The cache is independently bounded by entry count and owned DER bytes.
    count_cases=[]
    for serial in range(410,420):
        item=certificate(serial,"Eviction leaf",issuer=root,dns_name="example.com")
        envelope=signed_proof("example.com",item,[])
        if not count_cases: first_count=envelope
        count_cases.append(verify(envelope,root[1],True,"entry-count eviction",clear=not count_cases))
    count_evicted=verify(first_count,root[1],True,"oldest count entry evicted")
    held_replay=verify(good,root[1],True,"held proof survives cache clear and eviction")
    requests[held_replay]["replay_held"]=True
    byte_cases=[]
    for serial in range(430,436):
        key,cert=certificate(serial,"Padded leaf",issuer=root,dns_name="example.com")
        cert=reissue(cert,root[0],padding=12000)
        envelope=signed_proof("example.com",(key,cert),[])
        if not byte_cases: first_bytes=envelope
        byte_cases.append(verify(envelope,root[1],True,"DER-byte eviction",clear=not byte_cases))
    bytes_evicted=verify(first_bytes,root[1],True,"oldest byte entry evicted")
    # An oversized test trust anchor is legal for this test-only API but must
    # never enter the cache. Wire certificate entries remain capped at 16KiB.
    huge_root=(root[0],reissue(root[1],root[0],padding=35000))
    huge_leaf=(leaf[0],reissue(leaf[1],root[0],padding=12000))
    huge_proof=signed_proof("example.com",huge_leaf,[])
    oversize1=verify(huge_proof,huge_root[1],True,"oversized edge bypasses cache",clear=True)
    oversize2=verify(huge_proof,huge_root[1],True,"oversized edge still reverified")
    # Both certificate-message cache budgets independently bypass retention.
    # These remain wire-valid and execute all verification checks on every use.
    bypass_warm=verify(good,root[1],True,"warm A before oversized messages",clear=True)
    padded_root=reissue(root[1],root[0],padding=12000)
    payload_large=signed_proof("example.com",huge_leaf,[padded_root,padded_root])
    payload_cases=[verify(payload_large,root[1],True,"certificate payload budget bypass") for _ in range(2)]
    # Eight small certificates fit the raw-byte budget but exceed the reserved
    # public-key/parsed-structure budget. An unused candidate remains checked.
    structure_cases=[verify(duplicate,root[1],True,"certificate parsed-allocation budget bypass") for _ in range(2)]
    bypass_restored=verify(good,root[1],True,"warm A survives oversized messages")
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
        assert value["cache_entries"]<=8 and value["cache_bytes"]<=65536,(name,value)
        assert value["metadata_entries"]<=4 and value["metadata_bytes"]<=65536,(name,value)
        assert value["metadata_estimated_bytes"]<=262144,(name,value)
        if name=="valid work miss": assert value["meets_target"] is False
    assert results[cold]["work_hash"]==reference.connection_work_hash
    assert results[warm]["work_hash"]==reference.connection_work_hash
    assert results[cold]["cache_hits"]==0 and results[cold]["cache_entries"]==1
    assert results[warm]["cache_hits"]>results[cold]["cache_hits"]
    assert results[cold]["metadata_builds"]==results[warm]["metadata_builds"]==1
    assert results[warm]["metadata_hits"]>results[cold]["metadata_hits"]
    assert results[warm]["time_checks"]>results[cold]["time_checks"]
    assert all(results[index]["metadata_builds"]==1 for index in dates)
    assert results[dates[-1]]["time_checks"]==results[warm]["time_checks"]+len(dates)
    assert results[invalid_cv]["cache_hits"]>results[warm]["cache_hits"]
    assert results[changed_parent]["cache_misses"]>results[before_parent]["cache_misses"]
    assert results[changed_parent_hit]["cache_hits"]>results[changed_parent]["cache_hits"]
    assert results[child_bad2]["cache_misses"]>results[child_bad1]["cache_misses"]
    assert results[child_bad2]["cache_entries"]==results[child_bad1]["cache_entries"]
    assert results[ku_first]["metadata_builds"]>results[before_usage]["metadata_builds"]
    assert results[ku_again]["metadata_builds"]==results[ku_first]["metadata_builds"]
    assert results[ku_again]["metadata_hits"]>results[ku_first]["metadata_hits"]
    assert results[metadata_restored]["metadata_builds"]>results[ku_again]["metadata_builds"]
    assert results[reuse_cold]["context_reused"] is False
    assert results[reuse_time]["context_reused"] is True
    assert results[reuse_expired]["context_reused"] is True
    assert results[reuse_restored]["context_reused"] is True
    assert results[reuse_restored]["metadata_builds"]==1
    assert results[reuse_time]["work_hash"]==results[reuse_restored]["work_hash"]==reference.connection_work_hash
    assert all(results[index]["context_reused"] is False for index in (reuse_target,reuse_mask,reuse_domain))
    assert [results[index]["metadata_builds"] for index in (lru_a,lru_aa,lru_b,lru_aba)]==[1,1,2,2]
    assert results[lru_full]["metadata_entries"]==4
    assert results[lru_a_kept]["metadata_builds"]==results[lru_full]["metadata_builds"]
    assert results[lru_b_evicted]["metadata_builds"]==results[lru_a_kept]["metadata_builds"]+1
    for index in malformed_cases:
        assert results[index]["metadata_builds"]==results[lru_b_evicted]["metadata_builds"]
        assert results[index]["metadata_entries"]==results[lru_b_evicted]["metadata_entries"]
        assert results[index]["metadata_bytes"]==results[lru_b_evicted]["metadata_bytes"]
    assert results[malformed_cases[1]]["metadata_misses"]==results[malformed_cases[0]]["metadata_misses"]+1
    assert results[malformed_restored]["metadata_builds"]==results[lru_b_evicted]["metadata_builds"]
    assert results[parallel]["metadata_builds"]==results[malformed_restored]["metadata_builds"]
    assert results[parallel]["metadata_hits"]==results[malformed_restored]["metadata_hits"]+1
    assert results[count_cases[-1]]["cache_entries"]==8
    assert results[count_cases[-1]]["metadata_entries"]==4
    assert results[count_evicted]["cache_misses"]>results[count_cases[-1]]["cache_misses"]
    assert results[count_evicted]["metadata_builds"]==results[count_cases[-1]]["metadata_builds"]+1
    assert results[held_replay]["metadata_builds"]==results[count_evicted]["metadata_builds"]+1
    assert results[held_replay]["work_hash"]==reference.connection_work_hash
    assert results[byte_cases[-1]]["cache_entries"]<8
    assert results[byte_cases[-1]]["metadata_entries"]==2
    assert results[bytes_evicted]["cache_misses"]>results[byte_cases[-1]]["cache_misses"]
    assert results[bytes_evicted]["metadata_builds"]==results[byte_cases[-1]]["metadata_builds"]+1
    assert results[oversize1]["cache_entries"]==results[oversize2]["cache_entries"]==0
    assert results[oversize1]["cache_bytes"]==results[oversize2]["cache_bytes"]==0
    assert results[oversize2]["cache_misses"]>results[oversize1]["cache_misses"]
    for index in payload_cases+structure_cases:
        assert results[index]["metadata_entries"]==results[bypass_warm]["metadata_entries"]==1
        assert results[index]["metadata_bytes"]==results[bypass_warm]["metadata_bytes"]
        assert results[index]["metadata_estimated_bytes"]==results[bypass_warm]["metadata_estimated_bytes"]
    assert results[payload_cases[1]]["metadata_builds"]==results[payload_cases[0]]["metadata_builds"]+1
    assert results[structure_cases[1]]["metadata_builds"]==results[structure_cases[0]]["metadata_builds"]+1
    assert results[bypass_restored]["metadata_builds"]==results[bypass_warm]["metadata_builds"]+4
    assert results[bypass_restored]["metadata_hits"]==results[bypass_warm]["metadata_hits"]+1
    print(f"{len(expected)} native crypto fixture cases passed")
if __name__=="__main__": main()
