from dotenv import load_dotenv
load_dotenv()

from fastmcp import FastMCP
from opensearch_tools import mcp 


if __name__ == "__main__":
    mcp.run()