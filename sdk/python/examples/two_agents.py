"""Two scripted agent workers, with owner review. No model/provider calls.

Set DOLPHI_URL and DOLPHI_OWNER_TOKEN_FILE. Credentials are never printed.
"""
import os
from pathlib import Path
from dolphi import Client, DolphiError


def run():
    url = os.environ["DOLPHI_URL"]
    owner = Client(url,Path(os.environ["DOLPHI_OWNER_TOKEN_FILE"]).read_text().strip())
    inventory = Client(url,owner.create_agent(300)["secret"])
    summary = Client(url,owner.create_agent(300)["secret"])
    inventory.remember("supplier-note","Private supplier quote")
    summary.remember("task","Summarize approved stock")
    assert summary.recall("supplier-note") is None
    before = summary.read_shared("stock")
    proposal = inventory.propose("stock","12 units")
    assert summary.read_shared("stock") == before
    try: inventory.approve(proposal)
    except DolphiError as error: assert error.status == 403
    else: raise AssertionError("agent obtained approval authority")
    # Deterministic demo owner policy; a real UI must show the proposal and
    # obtain human approval. Do not give this owner client to an LLM.
    assert owner.inspect(proposal)["value"] == "12 units"
    owner.approve(proposal)
    summary.remember("summary",summary.read_shared("stock")["value"])
    assert summary.recall("summary") == "12 units"
    print("PASS: two authenticated workers, isolated memory, owner approval and shared summary")


if __name__ == "__main__": run()
