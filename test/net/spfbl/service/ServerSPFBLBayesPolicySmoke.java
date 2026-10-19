/*
 * This file is part of SPFBL.
 *
 * SPFBL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package net.spfbl.service;

import net.spfbl.core.Action;
import net.spfbl.core.Filterable;

public final class ServerSPFBLBayesPolicySmoke {

    private ServerSPFBLBayesPolicySmoke() {
    }

    public static void main(String[] args) {
        require(ServerSPFBL.isBayesEligibleFilter(null, Action.FLAG),
                "Bayes must inspect messages without an earlier content filter.");
        require(ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.HREF_SUSPECT, Action.FLAG),
                "Bayes must inspect suspicious-link messages that would only be flagged.");
        require(ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.SPF_FAIL, Action.FLAG),
                "Bayes must inspect soft SPF failures when policy only flags them.");
        require(!ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.HREF_SUSPECT, Action.REJECT),
                "A result already rejected by the configured reputation policy needs no Bayes override.");
        require(!ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.HREF_SUSPECT, Action.HOLD),
                "An explicit hold policy must retain priority over Bayes.");
        require(!ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.ORIGIN_WHITE_KEY_ADMIN, Action.FLAG),
                "Bayes must not override an explicit administrator whitelist.");
        require(!ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.MALWARE_NOT_IGNORED, Action.FLAG),
                "Bayes must not replace a definitive malware decision.");
        require(!ServerSPFBL.isBayesEligibleFilter(Filterable.Filter.ORIGIN_BANNED, Action.FLAG),
                "Bayes must not replace a definitive block decision.");
        System.out.println("PASS: Bayes checks soft FLAG results without overriding whitelist, hold, reject, or block.");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
