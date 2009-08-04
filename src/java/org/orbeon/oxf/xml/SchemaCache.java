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
package org.orbeon.oxf.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.httpclient.HttpException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.orbeon.oxf.resources.URLFactory;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * @author bardashevsky
 *
 * Mar 24, 2008 7:37:03 PM
 */
public class SchemaCache implements EntityResolver {
	private static final Logger log = Logger.getLogger(SchemaCache.class);

    private static final String DEFAULT_CACHE_FOLDER = System.getProperty("user.home") + "/OrbeonSchemaCache";
	private static final String SCHEMA_PROPERTIES = "schemaCache.xml";
	private static final String FOLDER_SEPARATOR = "/";
	private static final String FILE_SUFFIX = ".data";
    private static String cacheFolder = DEFAULT_CACHE_FOLDER;

	static {
		String orbeonCacheFolder = System.getProperty("orbeon.schema.cache.folder");
		if (orbeonCacheFolder != null) {
			cacheFolder = orbeonCacheFolder;
		}
	}

	private Properties cache = new Properties();;

	public SchemaCache() {
		init();
	}

    private String doCacheSchema(String systemId) throws IOException {
		if (log.isDebugEnabled()) {
			log.debug("Trying to resolve URL: " + systemId);
		}

    	InputStream is = loadUrl(systemId);

        File file = new File(getCacheFilePath());
        FileOutputStream fos = new FileOutputStream(file);

        IOUtils.copy(is, fos);
        IOUtils.closeQuietly(fos);

        return file.getName();
    }

    private InputStream loadUrl(String urlStr) throws HttpException, IOException {
    	URL url = URLFactory.createURL(urlStr);
    	return url.openConnection().getInputStream();
	}

	public void init() {
        File cacheDir = new File(getCacheFolder());
        if(!cacheDir.exists()){
            cacheDir.mkdirs();
        }

        File indexFile = new File(getCacheIndexFilePath());
        if (indexFile.exists()) {
            try {
				cache.loadFromXML(new FileInputStream(indexFile));
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
        }
    }

    public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
        synchronized (cache) {
			try {
				if (StringUtils.isEmpty(publicId)) {
					return createInputSource(publicId, systemId, loadUrl(systemId));
				} else {
					if (cache.getProperty(publicId) == null) {
						cache.setProperty(publicId, doCacheSchema(systemId));

						if (log.isDebugEnabled()) {
							log.debug("Schema stored in cache: publicId = \"" + publicId + "\", systemId = \"" + systemId + "\"");
						}

						cache.storeToXML(new FileOutputStream(getCacheIndexFilePath()), null);
					}

					return getFromCache(publicId, systemId);
				}
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
		}
		return null;
	}

	private InputSource getFromCache(String publicId, String systemId) throws FileNotFoundException {
		if (log.isDebugEnabled()) {
			log.debug("Getting from cache: publicId = \"" + publicId + "\", systemId = \"" + systemId + "\"");
		}

		InputStream inputStream = new FileInputStream(getCacheFilePath(cache.getProperty(publicId)));
		return createInputSource(publicId, systemId, inputStream);
	}

	private InputSource createInputSource(String publicId, String systemId, InputStream inputStream) {
		InputSource inputSource = new InputSource(inputStream);

		inputSource.setPublicId(publicId);
		inputSource.setSystemId(systemId);
		return inputSource;
	}

	private String getCacheIndexFilePath() {
		return getCacheFolder() + SCHEMA_PROPERTIES;
	}

	private String getCacheFilePath() {
		return getCacheFilePath(UUID.randomUUID().toString() + FILE_SUFFIX);
	}

	private String getCacheFilePath(String fileName) {
		return getCacheFolder() + fileName;
	}

	public String getCacheFolder() {
		if (!cacheFolder.endsWith(FOLDER_SEPARATOR)) {
			return cacheFolder + FOLDER_SEPARATOR;
		}

		return cacheFolder;
	}
}
