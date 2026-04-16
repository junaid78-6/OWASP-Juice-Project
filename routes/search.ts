/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as models from '../models/index'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { QueryTypes } from 'sequelize'
import logger from '../lib/logger'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// Whitelist of allowed characters for search input
const SEARCH_INPUT_WHITELIST = /^[a-zA-Z0-9\s\-_.&%]*$/

// Function to sanitize and validate search input
function sanitizeSearchInput (input: string): string {
  // Remove leading/trailing whitespace
  let sanitized = input.trim()

  // Enforce maximum length
  sanitized = (sanitized.length <= 200) ? sanitized : sanitized.substring(0, 200)

  // Validate against whitelist pattern
  if (!SEARCH_INPUT_WHITELIST.test(sanitized)) {
    logger.warn(`Suspicious search input detected: ${sanitized}`)
    // Return only alphanumeric and safe characters
    sanitized = sanitized.replace(/[^a-zA-Z0-9\s\-_.]/g, '')
  }

  return sanitized
}

// Function to escape SQL LIKE wildcards
function escapeLikeWildcards (input: string): string {
  return input.replace(/[%_]/g, '\\$&')
}

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''

      // Sanitize and validate input
      criteria = sanitizeSearchInput(criteria)

      // Escape SQL LIKE wildcards to prevent wildcard-based attacks
      const escapedCriteria = escapeLikeWildcards(criteria)

      // Use parameterized query with escaped LIKE pattern
      models.sequelize.query(
        'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
        {
          type: QueryTypes.SELECT,
          replacements: { criteria: `%${escapedCriteria}%` }
        }
      ).then((products: any) => {
      const dataString = JSON.stringify(products)
      if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
        let solved = true
        UserModel.findAll().then(data => {
          const users = utils.queryResultToJson(data)
          if (users.data?.length) {
            for (let i = 0; i < users.data.length; i++) {
              solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
              if (!solved) {
                break
              }
            }
            if (solved) {
              challengeUtils.solve(challenges.unionSqlInjectionChallenge)
            }
          }
        }).catch((error: Error) => {
          next(error)
        })
      }
      if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
        let solved = true
        void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
          const tableDefinitions = utils.queryResultToJson(data)
          if (tableDefinitions.data?.length) {
            for (let i = 0; i < tableDefinitions.data.length; i++) {
              if (tableDefinitions.data[i].sql) {
                solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                if (!solved) {
                  break
                }
              }
            }
            if (solved) {
              challengeUtils.solve(challenges.dbSchemaChallenge)
            }
          }
        })
      } // vuln-code-snippet hide-end
      for (let i = 0; i < products.length; i++) {
        products[i].name = req.__(products[i].name)
        products[i].description = req.__(products[i].description)
      }
      res.json(utils.queryResultToJson(products))
    }).catch((error: ErrorWithParent) => {
      // Log suspicious database errors that might indicate SQL injection attempts
      if (error?.parent?.message?.includes('SQLITE_ERROR') || error?.parent?.message?.includes('syntax error')) {
        logger.warn(`Potential SQL injection attempt detected in search endpoint. Error: ${error?.parent?.message}. Input was sanitized.`)
      }
      next(error.parent)
    })
    } catch (err: unknown) {
      logger.error(`Search endpoint error: ${utils.getErrorMessage(err)}`)
      next(err)
    }
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
