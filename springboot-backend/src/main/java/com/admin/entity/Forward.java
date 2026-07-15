package com.admin.entity;

import java.io.Serializable;
import java.util.List;

import com.admin.common.dto.ForwardPortDto;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.extension.handlers.JacksonTypeHandler;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * <p>
 * 
 * </p>
 *
 * @author QAQ
 * @since 2025-06-03
 */
@Data
@EqualsAndHashCode(callSuper = false)
@TableName(autoResultMap = true)
public class Forward extends BaseEntity{

    private static final long serialVersionUID = 1L;

    private Integer userId;

    private String userName;

    private String name;

    private Integer tunnelId;

    private String remoteAddr;

    private String strategy;

    private Long inFlow;

    private Long outFlow;

    /** 转发到期时间（毫秒时间戳），0 或空表示永不过期 */
    private Long expTime;

    private Integer inx;
}
