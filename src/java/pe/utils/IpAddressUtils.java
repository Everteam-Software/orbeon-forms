/**
 *  Copyright (C) 2007-2009 Intalio, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify it under the terms of the
 *  GNU Lesser General Public License as published by the Free Software Foundation; either version
 *  2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  The full text of the license is available at http://www.gnu.org/copyleft/lesser.html
 */
package pe.utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Alexey Makarenko <br>
 *         date: 26/5/2008 <br>
 */
public class IpAddressUtils {

    /**
     * Pattern that matches ip4 format string: ddd.ddd.ddd.ddd
     */
    private static Matcher ip_regex = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}").matcher("");

    /**
     * Pattern that matches http[s] URI format string: http[s]://server[:port][/request]*[?query]
     */
    private static Matcher server_regex = Pattern.compile("http.?://([\\w\\.\\d]+)(:\\d+)?/?").matcher("");

    /**
     * Method tests host address specified in url string on occurrence in hosts array.
     * If host was defined as symbolic server name it will be resolved to ip4 address string.
     * If host's ip address cannot be resolved exception will be thrown.
     *
     * @param hosts array of host names and/or ip addresses.
     * @param url url to test against.
     * @return <code>true<code> if url host is contained in hosts array.
     * @throws java.net.UnknownHostException if symbolic server name cannot be resolved to ip address
     */
    public static boolean isHostsContainsUrlHost(final String [] hosts, final String url) throws UnknownHostException {

        final String hostName = getUrlHost(url);
        String hostAddress = hostName;

        if(!isIPAddress(hostName))
            hostAddress = getIPAddressByName(hostName);

        for(int i = 0; i<hosts.length; i++) {
            if(!isIPAddress(hosts[i])) {
                if(hostName.equalsIgnoreCase(hosts[i]))
                    return true;
                hosts[i] = getIPAddressByName(hosts[i]);
                if(hostAddress.equalsIgnoreCase(hosts[i]))
                    return true;
            } else {
                if(hostAddress.equalsIgnoreCase(hosts[i]))
                    return true;
            }
        }

        return Arrays.asList(hosts).contains(hostAddress);

    }

    /**
     * Extracts host name from url string.
     * @param url URL string
     * @return server name
     */
    public static String getUrlHost(final String url) {

        String host = null;

        final Matcher regex =  server_regex.reset(url);
        if(regex.find())
            host = regex.group(1);
        regex.reset();

        return host;
    }

    /**
     * Tests if parameter host is ip4 address string or not.
     * @param host string host address
     * @return true if host is ip4 string
     */
    public static boolean isIPAddress(final String host) {
        return ip_regex.reset(host).matches();
    }

    /**
     * Resolves symbolic server name to ip4 string address.
     * @param host server name
     * @return ip4 string address
     * @throws UnknownHostException if symbolic server name cannot be resolved to ip address
     */
    public static String getIPAddressByName(final String host) throws UnknownHostException {

        if(isIPAddress(host)) return host;

        final String ip = InetAddress.getByName(host).toString();

        return ip.substring(ip.indexOf('/') + 1);
    }

}
