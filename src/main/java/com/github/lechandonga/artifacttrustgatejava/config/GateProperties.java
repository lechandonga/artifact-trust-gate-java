package com.github.lechandonga.artifacttrustgatejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gate")
public class GateProperties {

    /** 本地“数据库”根目录，所有密钥/策略/审计都落在这里。 */
    private String dataDir = "gate-data";

    /** 启动时是否写入演示密钥与策略（v1/v2）。 */
    private boolean seedDemoData = true;

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public boolean isSeedDemoData() {
        return seedDemoData;
    }

    public void setSeedDemoData(boolean seedDemoData) {
        this.seedDemoData = seedDemoData;
    }
}
