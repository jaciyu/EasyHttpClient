package com.express.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="expressdata")
public class ExpressData {
	@Id
	@GeneratedValue
	private Integer id;
	@Column(name="expressnumber")
	private String expressNumber;
	@Column(name="statu")
	private Integer statu;
	@Column(name="status")
	private String status;
	@Column(name="createtime")
	private Date createTime = new Date();
	@Column(name="updatetime")
	private Date updateTime;
	@Column(name="finish")
	private Integer finish = 0;
	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public String getExpressNumber() {
		return expressNumber;
	}
	public void setExpressNumber(String expressNumber) {
		this.expressNumber = expressNumber;
	}
	public Integer getStatu() {
		return statu;
	}
	public void setStatu(Integer statu) {
		this.statu = statu;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public Date getCreateTime() {
		return createTime;
	}
	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}
	public Date getUpdateTime() {
		return updateTime;
	}
	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}
	public Integer getFinish() {
		return finish;
	}
	public void setFinish(Integer finish) {
		this.finish = finish;
	}
	
}
