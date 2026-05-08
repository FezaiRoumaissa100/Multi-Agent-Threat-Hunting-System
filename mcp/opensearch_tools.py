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


'''@mcp.tool()
def Search_index(query_json:str,index_name:str="wazuh-archive",size:int=10)->str:

    try:
        client=get_client()
        query=json.loads(query_json)
        response = client.search(
            index=index_name,
            body=query,
            size=size
        )
        hits = response.get("hits", {})
        return json.dumps(hits, indent=2)
    except json.JSONDecodeError as e:
        return f"Error parsing query_json. Please provide a valid JSON string. Error: {str(e)}"
    except Exception as e:
        return f"Error executing search on index '{index_name}': {str(e)}"
        '''
@mcp.tool()
def search_wazuh(lucene_query: str, index_name: str = "wazuh-archive") -> str:
    """
    Search the OpenSearch archives using a Lucene query string.
    Agent: Use this tool to search for alerts, logs, and events.
    
    Args:
        lucene_query: A valid Lucene query string (e.g. 'rule.description:"SSH failed" AND data.srcip:"192.168.100.30"').
        index_name: The target index. Defaults to 'wazuh-archive'.
    """
    try:
        client = get_client()
        query_body = {
            "size": 10,
            "query": {
                "query_string": {
                    "query": lucene_query
                }
            }
        }
        
        response = client.search(index=index_name, body=query_body)
        
        # Extract just the hits from the response to reduce context bloat
        hits = response.get("hits", {})
        return json.dumps(hits, indent=2)
    except Exception as e:
        return f"Error executing search: {str(e)}"