"""Shared packet-parsing library (owner: Person 4). Public API: decode.decode(), flows.FlowAssembler.

Both the live capture module and the historical forensics module consume it; neither owns it. Changes follow the
contract-change policy because every flow in the system is shaped here.
"""
from nextrace.parsing.decode import decode
from nextrace.parsing.flows import AssemblerStats, FlowAssembler

__all__ = ["decode", "FlowAssembler", "AssemblerStats"]
