#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec } from 'child_process';

const execAsync = promisify(exec);

class IdaProMCPServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: 'ida-pro-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    
    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'run_ida_command',
            description: 'Execute an IDA Pro Script (IdaPython, Version IDA 8.3)',
            inputSchema: {
              type: 'object',
              properties: {
                script: {
                  type: 'string',
                  description: 'The IdaPython script to execute'
                }
              },
              required: ['script']
            }
          },
          {
            name: 'run_ida_command_filebased',
            description: '(FOR IDE USAGE) Execute an IDA Pro Script (IdaPython, Version IDA 8.3)',
            inputSchema: {
              type: 'object',
              properties: {
                scriptPath: {
                  type: 'string',
                  description: 'Path to the IdaPython script file'
                },
                outputPath: {
                  type: 'string',
                  description: 'Path where output will be written'
                }
              },
              required: ['scriptPath', 'outputPath']
            }
          },
          {
            name: 'search_immediate_value',
            description: 'Search for immediate values in the binary',
            inputSchema: {
              type: 'object',
              properties: {
                value: {
                  type: 'string',
                  description: 'The immediate value to search for'
                },
                radix: {
                  type: 'integer',
                  description: 'The radix (base) for the value (e.g., 10 for decimal, 16 for hex)',
                  default: 16
                },
                startAddress: {
                  type: 'string',
                  description: 'Start address for search (optional)'
                },
                endAddress: {
                  type: 'string',
                  description: 'End address for search (optional)'
                }
              },
              required: ['value']
            }
          },
          {
            name: 'search_text',
            description: 'Search for text in the binary',
            inputSchema: {
              type: 'object',
              properties: {
                text: {
                  type: 'string',
                  description: 'The text to search for'
                },
                caseSensitive: {
                  type: 'boolean',
                  description: 'Whether the search should be case sensitive',
                  default: false
                },
                startAddress: {
                  type: 'string',
                  description: 'Start address for search (optional)'
                },
                endAddress: {
                  type: 'string',
                  description: 'End address for search (optional)'
                }
              },
              required: ['text']
            }
          },
          {
            name: 'search_byte_sequence',
            description: 'Search for a byte sequence in the binary',
            inputSchema: {
              type: 'object',
              properties: {
                bytes: {
                  type: 'string',
                  description: 'The byte sequence to search for (hex format, e.g., "48 8B 05")'
                },
                startAddress: {
                  type: 'string',
                  description: 'Start address for search (optional)'
                },
                endAddress: {
                  type: 'string',
                  description: 'End address for search (optional)'
                }
              },
              required: ['bytes']
            }
          },
          {
            name: 'get_disassembly',
            description: 'Get disassembly for an address range',
            inputSchema: {
              type: 'object',
              properties: {
                startAddress: {
                  type: 'string',
                  description: 'Start address for disassembly'
                },
                endAddress: {
                  type: 'string',
                  description: 'End address for disassembly (optional)'
                },
                count: {
                  type: 'integer',
                  description: 'Number of instructions to disassemble (optional)',
                  default: 10
                }
              },
              required: ['startAddress']
            }
          },
          {
            name: 'get_functions',
            description: 'Get list of functions from the binary',
            inputSchema: {
              type: 'object',
              properties: {},
              required: []
            }
          },
          {
            name: 'get_exports',
            description: 'Get list of exports from the binary',
            inputSchema: {
              type: 'object',
              properties: {},
              required: []
            }
          },
          {
            name: 'search_in_names',
            description: 'Search for names/symbols in the binary',
            inputSchema: {
              type: 'object',
              properties: {
                pattern: {
                  type: 'string',
                  description: 'The pattern to search for in names/symbols'
                },
                caseSensitive: {
                  type: 'boolean',
                  description: 'Whether the search should be case sensitive',
                  default: false
                },
                type: {
                  type: 'string',
                  description: 'Type of names to search (functions, data, etc.)',
                  enum: ['all', 'functions', 'data']
                }
              },
              required: ['pattern']
            }
          },
          {
            name: 'get_xrefs_to',
            description: 'Get cross-references to an address',
            inputSchema: {
              type: 'object',
              properties: {
                address: {
                  type: 'string',
                  description: 'The address to get cross-references to'
                },
                type: {
                  type: 'string',
                  description: 'Type of cross-references (code, data, or all)',
                  enum: ['code', 'data', 'all'],
                  default: 'all'
                }
              },
              required: ['address']
            }
          },
          {
            name: 'get_xrefs_from',
            description: 'Get cross-references from an address',
            inputSchema: {
              type: 'object',
              properties: {
                address: {
                  type: 'string',
                  description: 'The address to get cross-references from'
                },
                type: {
                  type: 'string',
                  description: 'Type of cross-references (code, data, or all)',
                  enum: ['code', 'data', 'all'],
                  default: 'all'
                }
              },
              required: ['address']
            }
          },
          {
            name: 'get_strings',
            description: 'Get list of strings from the binary',
            inputSchema: {
              type: 'object',
              properties: {},
              required: []
            }
          }
        ]
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'run_ida_command':
            return await this.runIdaCommand(args.script);
          case 'run_ida_command_filebased':
            return await this.runIdaCommandFileBased(args.scriptPath, args.outputPath);
          case 'search_immediate_value':
            return await this.searchImmediateValue(args.value, args.radix, args.startAddress, args.endAddress);
          case 'search_text':
            return await this.searchText(args.text, args.caseSensitive, args.startAddress, args.endAddress);
          case 'search_byte_sequence':
            return await this.searchByteSequence(args.bytes, args.startAddress, args.endAddress);
          case 'get_disassembly':
            return await this.getDisassembly(args.startAddress, args.endAddress, args.count);
          case 'get_functions':
            return await this.getFunctions();
          case 'get_exports':
            return await this.getExports();
          case 'search_in_names':
            return await this.searchInNames(args.pattern, args.caseSensitive, args.type);
          case 'get_xrefs_to':
            return await this.getXrefsTo(args.address, args.type);
          case 'get_xrefs_from':
            return await this.getXrefsFrom(args.address, args.type);
          case 'get_strings':
            return await this.getStrings();
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        throw new McpError(
          ErrorCode.InternalError,
          `Error executing tool ${name}: ${error}`
        );
      }
    });
  }

  private async runIdaCommand(script: string) {
    // This would execute an IdaPython script
    // For now, return a placeholder response
    return {
      content: [
        {
          type: 'text',
          text: `Executing IdaPython script:\n${script}\n\nNote: This is a placeholder. In a real implementation, this would execute the script in IDA Pro.`
        }
      ]
    };
  }

  private async runIdaCommandFileBased(scriptPath: string, outputPath: string) {
    return {
      content: [
        {
          type: 'text',
          text: `Executing IdaPython script from file: ${scriptPath}\nOutput will be written to: ${outputPath}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async searchImmediateValue(value: string, radix: number = 16, startAddress?: string, endAddress?: string) {
    return {
      content: [
        {
          type: 'text',
          text: `Searching for immediate value: ${value} (base ${radix})\nStart: ${startAddress || 'beginning'}\nEnd: ${endAddress || 'end'}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async searchText(text: string, caseSensitive: boolean = false, startAddress?: string, endAddress?: string) {
    return {
      content: [
        {
          type: 'text',
          text: `Searching for text: "${text}"\nCase sensitive: ${caseSensitive}\nStart: ${startAddress || 'beginning'}\nEnd: ${endAddress || 'end'}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async searchByteSequence(bytes: string, startAddress?: string, endAddress?: string) {
    return {
      content: [
        {
          type: 'text',
          text: `Searching for byte sequence: ${bytes}\nStart: ${startAddress || 'beginning'}\nEnd: ${endAddress || 'end'}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async getDisassembly(startAddress: string, endAddress?: string, count: number = 10) {
    return {
      content: [
        {
          type: 'text',
          text: `Getting disassembly from: ${startAddress}\nTo: ${endAddress || `${count} instructions`}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async getFunctions() {
    return {
      content: [
        {
          type: 'text',
          text: 'Getting list of functions from binary...\n\nNote: This is a placeholder implementation.'
        }
      ]
    };
  }

  private async getExports() {
    return {
      content: [
        {
          type: 'text',
          text: 'Getting list of exports from binary...\n\nNote: This is a placeholder implementation.'
        }
      ]
    };
  }

  private async searchInNames(pattern: string, caseSensitive: boolean = false, type: string = 'all') {
    return {
      content: [
        {
          type: 'text',
          text: `Searching for pattern "${pattern}" in names/symbols\nCase sensitive: ${caseSensitive}\nType: ${type}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async getXrefsTo(address: string, type: string = 'all') {
    return {
      content: [
        {
          type: 'text',
          text: `Getting cross-references to address: ${address}\nType: ${type}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async getXrefsFrom(address: string, type: string = 'all') {
    return {
      content: [
        {
          type: 'text',
          text: `Getting cross-references from address: ${address}\nType: ${type}\n\nNote: This is a placeholder implementation.`
        }
      ]
    };
  }

  private async getStrings() {
    return {
      content: [
        {
          type: 'text',
          text: 'Getting list of strings from binary...\n\nNote: This is a placeholder implementation.'
        }
      ]
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('IDA Pro MCP server running on stdio');
  }
}

const server = new IdaProMCPServer();
server.run().catch(console.error);