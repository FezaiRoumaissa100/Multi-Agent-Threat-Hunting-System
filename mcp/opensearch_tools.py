import json
from fastmcp import FastMCP
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mcp_client import get_client

mcp=FastMCP("Opensearch MCP Server")


@mcp.tool()
def get_index_mapping(index_name:str)->str:
    """Get the mapping of an index"""
    try : 
        client=get_client()
        mapping=client.indices.get_mapping(index=index_name)
        return json.dumps(mapping,indent=2)
    except Exception as e:
        return f"Error getting index mapping: {str(e)}"