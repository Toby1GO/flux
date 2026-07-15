package com.admin.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.List;
import java.util.Map;

/** 为已有 SQLite 数据库执行向后兼容的轻量迁移。 */
@Slf4j
@Component
public class DatabaseMigration implements ApplicationRunner {

    @Resource
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(ApplicationArguments args) {
        List<Map<String, Object>> columns = jdbcTemplate.queryForList("PRAGMA table_info(forward)");
        boolean hasExpTime = columns.stream()
                .anyMatch(column -> "exp_time".equalsIgnoreCase(String.valueOf(column.get("name"))));
        if (!hasExpTime) {
            jdbcTemplate.execute("ALTER TABLE forward ADD COLUMN exp_time INTEGER NOT NULL DEFAULT 0");
            log.info("数据库迁移完成：forward.exp_time");
        }

        boolean hasFlow = columns.stream()
                .anyMatch(column -> "flow".equalsIgnoreCase(String.valueOf(column.get("name"))));
        if (!hasFlow) {
            jdbcTemplate.execute("ALTER TABLE forward ADD COLUMN flow INTEGER NOT NULL DEFAULT 0");
            log.info("数据库迁移完成：forward.flow");
        }
    }
}
