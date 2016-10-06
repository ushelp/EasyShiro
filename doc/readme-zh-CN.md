# EasyShiro

---------------

## 简介
- **Apache Shiro**

  [Apache Shiro](http://shiro.apache.org/ " Apache Shiro ") 是目前最为强大和全面的 Java 安全管理框架，提供用户认证，授权（基于角色和权限），Session 管理，加密，Web及第三方集成等等。但 Apache Shiro 只是一个安全引擎，并非一个权限管理系统，日常项目的权限管理系统仍需自行实现，不同的项目往往需要自定义众多不同的安全组件，而且配置繁复。

- **EasyShiro**

  EasyShiro 是一个基于 Shiro 的安全扩展组件。为基于数据库权限管理和 **Web URL 授权**的RBAC（Role Based Access Control） Web 权限模型，提供通用的 Shiro 安全管理支持。

  使用 EasyShiro， 仅需简单配置即可将 Shiro 的强大功能应用到项目中去，减少 Shiro 的复杂性，**简化安全集成**，并增强其功能，提供通用的**验证码**，**自动登录**，**登录锁定**，**错误消息配置**，**拦截器**，**Ajax 响应**等等支持。

  EasyShiro 提供了完整的**通用配置模板**(`shiro.ini`, `spring-shiro.xml`)，仅需加入 jar 包，按需求调整部分配置选项，即可完成集成，享受完整的 Shiro 支持。


## 主要特点



### 1. 增强简化的 Shiro 统一组件支持

- **Auth**：`EasyFormAuthenticationFilter`，功能全面的认证过滤器，提供验证码（CAPTCHA），自动登录（AutoLogin），登录锁定（LockLogin），异常消息自定义（exceptionMsg），重定向跳转，拦截器，多次登录等等功能

- **Realm**：`EasyJdbcRealm`，基于数据库的Realm，从数据库自动获取认证和授权数据，支持权限刷新

- **Perms**：`EasyURLPermissionFilter`，授权管理过滤器，基于Web 请求 URL 的授权管理，支持 Ajax 响应

- **Logout**：`EasyLogoutFilter`，用户注销过滤器，提供自动登录相关的注销

- **Interceptor**：认证与 Realm 拦截器支持(`EasyAuthenticationInterceptor`，`EasyJdbcRealmInterceptor`)，支持在认证成功或失败时进行扩展

- **EasyUsernamePasswordEndcodeToken**：简化并方案更加灵活的密码加密Token，实现 `encodePassword()`，返回密码加密后的结果

- **Exception**：登录认证相关自定义异常（`EasyIncorrectCaptchaException`，`EasyLockIPException`，`EasyLockUserException`，`EasyLockLoginException`）



### 2. 登录锁定管理系统 LockLoginManagement
 ![LockLogin](images/locklogin1.png)


## RBCA 模型
下面展示和提供了一个常见的基于数据库权限管理，菜单授权， Web URL 授权的 RBAC（Role Based Access Control） Web 权限模型。

 ![RBCA](images/rbca.png)



## 使用步骤

### 1.加入 jar 依赖
```XML
<dependency>
    <groupId>cn.easyproject</groupId>
    <artifactId>easyshiro</artifactId>
    <version>2.3.0-RELEASE</version>
</dependency>
```

### 2. 配置模板

#### 2.1 扩展配置，按需调整

- **EasyJdbcRealm**
 -  配置密码列（`passwordColumn`）
 -  认证语句（`authenticationQuery`）
 -  角色查询语句（`userRolesQuery`）
 -  权限查询语句（`permissionsQuery`）
 -  查询语句中支持多个`?`占位符（有利于 `union` 查询）。


- **EasyFormAuthenticationFilter**
 - **扩展基本配置**
 - 登录成功存入 session 的 Token 名 （`sessionTokenKey`）
 - 是否开启登录重定向（`loginFailureRedirectToLogin`）
 - 登录使用的扩展 Token 类完全限定名（`tokenClassName`）
 - 认证成功或失败自定义拦截器（`interceptor`），需要实现 `EasyAuthenticationInterceptor` 接口
 -  **CAPTCHA 验证码配置**
 - 是否开启验证码（`enableCaptcha`）
 - 验证码参数名（`captchaParam`）
 - session中存储的验证码名 （`sessionCaptchaKey`）
 -  **AutoLogin 自动登录配置**
 - 是否开启自动登录（`enableAutoLogin`）
 - 自动登录参数名（`autoLoginParam`）
 - 自动登录 Cookie 最大存储时间（`autoLoginMaxAge`）
 - 自动登录 Cookie 的 path（`autoLoginPath`）
 - 自动登录 Cookie 的 domain（`autoLoginDomain`）
 - **LockLogin 登录锁定**
 - 是否开启登录锁定功能（`enableLockLogin`）
 - 登录锁定使用的 Shiro EhCache 缓存管理器（`ehCacheManager`）
 - 登录检测 EhCache 缓存名（`lockCheckCacheName`）
 - 登录锁定 EhCache 缓存名（`lockLoginCacheName`）
 - 用户名锁定达到的最大登录错误次数（`userLock`）
 - IP锁定达到的最大登录错误次数（`ipLock`）
 - 基于IP的达到指定登录错误次数，显示验证码（`showCaptcha`）
 - **登录失败相关错误消息**
 - request 或 session 存储消息的名称（`msgKey`）
 - 消息是否存入 session（`sessionMsg`）
 - 消息是否存入 request（`requestMsg`）
 - 异常消息 Map 定义（`exceptionMsg`），格式 `ExceptionSimpleClassName=Message`


- **EasyURLPermissionFilter**
 -  是否开启登录超时检测（`authenticationTimeoutCheck`）
 -  权限验证失败，Ajax 消息 key（`msg`）
 -  权限验证失败，Ajax 状态码 key（`statusCode`）
 -  将消息存入 session（`sessionMsg`）
 -  将消息存入 request（`requestMsg`）
 -  授权失败提示内容（`permissionDeniedMsg`）
 -  登录超时提示内容（`authenticationTimeoutMsg`）


#### 2.2 Spring 配置模板 spring-shiro.xml
```XML
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:p="http://www.springframework.org/schema/p"
	xmlns:tx="http://www.springframework.org/schema/tx" xmlns:aop="http://www.springframework.org/schema/aop"
	xmlns:context="http://www.springframework.org/schema/context"
	xsi:schemaLocation="http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop-4.1.xsd
		http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.1.xsd
		http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context-4.1.xsd
		http://www.springframework.org/schema/tx http://www.springframework.org/schema/tx/spring-tx.xsd">


    <!-- Session 过期验证移除 -->
    <!-- SessionValidationScheduler 
    # Sessions are only validated to see 
    # if they have been stopped or expired at the time they are accessed, 
    # A SessionValidationScheduler is responsible for validating sessions 
    # at a periodic rate to ensure they are cleaned up as necessary.
    # You can custom SessionValidationScheduler implementation class.
    -->
    <bean id="sessionValidationScheduler" class="org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler">
        <!-- Default is 3,600,000 millis = 1 hour -->
        <property name="interval" value="3600000"></property>
    </bean>
    
    <!-- Session DAO -->
    <bean id="sessionDAO" class="org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO">
        <!-- This name matches a cache name in ehcache.xml -->
        <!-- <property name="activeSessionsCacheName" value="shiro-activeSessionsCache"></property> -->
    </bean>
    
    <!-- Session Manager -->
    <bean id="sessionManager" class="org.apache.shiro.web.session.mgt.DefaultWebSessionManager">
        <!-- Session Timeout: 3,600,000 milliseconds = 1 hour-->
        <property name="globalSessionTimeout" value="3600000"></property> 
        <property name="sessionValidationScheduler" ref="sessionValidationScheduler"></property>
        <property name="sessionValidationSchedulerEnabled" value="true"></property>
        <property name="sessionDAO" ref="sessionDAO"></property>
    </bean>
    
    <!-- Cache: EhCache-->
    <bean id="ehCacheManager"
    class="org.springframework.cache.ehcache.EhCacheManagerFactoryBean">
        <property name="configLocation" value="classpath:/ehcache.xml" />
        <property name="shared" value="true" />
        </bean>
        <!-- <bean id="cacheManager" class="org.springframework.cache.ehcache.EhCacheCacheManager">
        <property name="cacheManager" ref="ehCacheManager" />
        </bean> -->
        <bean id="shiroCacheManager" class="org.apache.shiro.cache.ehcache.EhCacheManager">
        <property name="cacheManager" ref="ehCacheManager" />
    </bean>
    
    <!-- RememberMeManager -->
    <bean id="cookie" class="org.apache.shiro.web.servlet.SimpleCookie">
        <!-- cookie name  -->
        <property name="name" value="rememberMe"></property>
        <!--  default is /request.getContextPath() -->
        <property name="path" value="/"></property> 
        <!-- default is ONE_YEAR -->
        <property name="maxAge" value="31536000"></property> 
        </bean>
        <bean id="rememberMeManager" class="org.apache.shiro.web.mgt.CookieRememberMeManager">
        <property name="cookie" ref="cookie"></property>
    </bean>

	
    	<!-- EasyJdbcRealm -->
    <bean id="jdbcRealm" class="cn.easyproject.easyshiro.EasyJdbcRealm">
        <property name="dataSource" ref="dataSource"></property>
        <!-- 认证信息查询语句; default: select * from users where username = ? -->
        <!-- 用户状态：0启用; 1禁用; 2删除 -->
        <property name="authenticationQuery" value="select user_id as userid,name,password,status,real_name as realname from sys_user where name=? and status in(0,1)"></property>
        <!-- 密码列列名; default: password -->
        <property name="passwordColumn" value="password"></property>
        <!-- 角色查询语句(支持多个username=?); default: select role_name from user_roles where username = ?  -->
        <property name="userRolesQuery" value="select name from sys_role where role_id in (select role_id from sys_user_role where user_id=(select user_id from sys_user where name=?)) and status=0"></property>
        <!-- 是否执行permissionsQuery权限查询; default: true -->
        <property name="permissionsLookupEnabled" value="true"></property>
        <!-- 权限查询语句(支持多个username=?); default: select permission from user_roles_permissions where username = ?"  -->
        <property name="permissionsQuery" value="select action from sys_menu_permission where MENU_PERMISSION_ID in( select MENU_PERMISSION_ID from sys_role_menu_permission where ROLE_ID in(select role_id from sys_user_role where user_id=(select user_id from sys_user where name=?))) UNION select action from sys_operation_permission where OPERATION_PERMISSION_ID in(select OPERATION_PERMISSION_ID from sys_role_operation_permission where ROLE_ID in(select role_id from sys_user_role where user_id=(select user_id from sys_user where name=?)))"></property>
        <!-- EasyJdbcRealm 拦截器，可以认证和授权信息获得后，对SimpleAuthenticationInfo认证和SimpleAuthorizationInfo授权信息进行额外处理 -->
        <!-- <property name="interceptor" ref="realmInterceptor"></property> -->
    </bean>
	
    <!-- EasyShiro 自定义认证处理拦截器 -->
    <!-- EasyFormAuthenticationFilter 认证成功或失败拦截器 -->
    <bean id="authenticationInterceptor" class="cn.easyproject.easyee.ssh.sys.shiro.AuthenticationInterceptor"> </bean>
    <!-- EasyJdbcRealm 认证与授权信息处理拦截器 -->
    <bean id="realmInterceptor" class="cn.easyproject.easyee.ssh.sys.shiro.RealmInterceptor"> </bean>

    <!-- auth Login Authentication -->
    <bean id="auth" class="cn.easyproject.easyshiro.EasyFormAuthenticationFilter">
    
         <!-- ###### FormAuthenticationFilter Configuration ##### -->
         <!-- when request method is post execute login, else to login page view -->
         <property name="loginUrl" value="/toLogin.action"></property>
         <!-- redirect after successful login -->
         <property name="successUrl" value="/toMain.action"></property>
         <!-- name of request parameter with username; if not present filter assumes 'username' -->
         <property name="usernameParam" value="name"></property>
         <!-- name of request parameter with password; if not present filter assumes 'password' -->
         <property name="passwordParam" value="password"></property>
         <!-- does the user wish to be remembered?; if not present filter assumes 'rememberMe' -->
         <!-- <property name="rememberMeParam" value="rememberMe"></property> -->
         
         
         <!-- ###### EasyFormAuthenticationFilter Configuration ##### -->
         <!-- ## Login Configuration ## -->
         <!--  登录成功，将 token 存入 session 的 key; default is 'TOKEN' -->
         <property name="sessionTokenKey" value="TOKEN"></property>
         <!-- 是否使用登录失败以重定向方式跳转回登录页面; default is 'false' -->
         <property name="loginFailureRedirectToLogin" value="true"></property>
         
         
         <!-- ## User defined UsernamePasswordToken Configuration ## -->
         <!-- 自定义 UsernamePasswordToken; Default is 'org.apache.shiro.auth.UsernamePasswordToken' -->
         <property name="tokenClassName" value="cn.easyproject.easyee.ssh.sys.shiro.UsernamePasswordEncodeToken"></property>
         
         
         <!-- ## CAPTCHA Configuration ## -->
         <!-- 是否开启验证码验证; default 'true' -->
         <property name="enableCaptcha" value="true"></property>
         <!-- 验证码参数名; default 'captcha' -->
         <property name="captchaParam" value="captcha"></property>
         <!-- Session中存储验证码值的key; default 'captcha' -->
         <property name="sessionCaptchaKey" value="rand"></property>
         
         
         <!-- ## AutoLogin Configuration ## -->
         <!-- 是否开启自动登录 -->
         <property name="enableAutoLogin" value="false"></property>
         <!-- 自动登录参数数名 -->
         <property name="autoLoginParam" value="autoLogin"></property>
         <!-- Cookie maxAge ，default is ONE_YEAR -->
         <property name="autoLoginMaxAge" value="31536000"></property>
         <!-- Cookie path，default is "" -->
         <property name="autoLoginPath" value="/"></property>
         <!-- Cookie domain，empty or default is your current domain name -->
         <property name="autoLoginDomain" value=""></property>
         
         
         	    <!-- ## LockLogin Configuration ## -->
	    <!-- LockLogin 管理锁定时间周期的 EHCache 缓存名称-->
	    <!-- 只需调整timeToIdleSeconds，默认达到登录锁定次数，登录锁定  2 小时 -->
	    <!-- LockLogin name cache management locks EHCache time period-->
	    <!-- Simply adjust timeToIdleSeconds, the default number of times to reach the login lockout, login lockout 2 Hours-->
	    <!-- <cache
	       	    name="shiro-lockLoginCache"
	            maxElementsInMemory="100000"
	            eternal="false"
	            timeToIdleSeconds="0"
	            timeToLiveSeconds="7200"
	            diskExpiryThreadIntervalSeconds="600"
	            memoryStoreEvictionPolicy="LRU"
	            overflowToDisk="true"
	            diskPersistent="true">
	    </cache> -->
       
       <!-- LockLogin 统计登录错误次数时间周期的 EHCache 缓存名称 -->
       <!-- 只需调整timeToIdleSeconds，默认统计 10 分钟内的错误次数  -->
       <!-- EHCache caching name Lock Login login error statistics of the number of time periods -->
       <!-- Simply adjust timeToIdleSeconds, default statistics the number of errors in 10 minutes -->
       <!-- <cache
       	    name="shiro-lockCheckCache"
            maxElementsInMemory="100000"
            eternal="false"
            timeToIdleSeconds="0"
            timeToLiveSeconds="600"
            diskExpiryThreadIntervalSeconds="600"
            memoryStoreEvictionPolicy="LRU"
            overflowToDisk="true"
            diskPersistent="true">
    	</cache> -->
           
         <!-- 是否开启LockLogin用户登录锁定；默认为false，不开启 -->
         <property name="enableLockLogin" value="false"></property>
         <!-- Shiro CacheManager -->
         <property name="ehCacheManager" ref="shiroCacheManager"></property>
         <!-- LockLogin 管理锁定时间周期的 EHCache 缓存名称；默认为 shiro-lockLoginCache -->
         <property name="lockLoginCacheName" value="shiro-lockLoginCache"></property>
         <!-- LockLogin 统计登录错误次数时间周期的 EHCache 缓存名称；默认为 shiro-lockCheckCache -->
         <property name="lockCheckCacheName" value="shiro-lockCheckCache"></property>
         <!-- 同一用户名登录达到登录错误次数，登录锁定；0为不限制；默认为6 -->
         <property name="userLock" value="4"></property>
         <!--  同一IP登录达到错误次数，登录锁定；0为不限制；默认为15 -->
         <property name="ipLock" value="6"></property>
         <!-- 达到指定登录错误次数，显示验证码；-1为不控制验证码显示；默认为1 -->
         <property name="showCaptcha" value="4"></property>
         
         <!-- ## 登录失败相关错误消息 ## -->
         <!-- 登录失败，消息 key  -->
         <property name="msgKey" value="MSG"></property>
         <!-- 将消息存入session，session.setAttribute(MsgKey,xxxErrorMsg); default is 'false' -->
         <property name="sessionMsg" value="true"></property>
         <!-- 将消息存入request，request.setAttribute(MsgKey,xxxErrorMsg); default is 'false' -->
         <property name="requestMsg" value="true"></property>
         <!-- # 登录错误的，异常提示内容 Map-->
         <property name="exceptionMsg">
             <map>
                 <!-- ExceptionClassName:"Message", ExceptionClassName2:"Message2", ... -->
                 <entry key="LockedAccountException" value="账户锁定，请联系管理员解锁。"></entry>
                 
                 <entry key="AuthenticationException" value="用户名或密码有误！"></entry>
                 
                 <entry key="EasyIncorrectCaptchaException" value="验证码有误！"></entry>
                 <entry key="EasyLockUserException" value="由于该用户连续登录错误，暂时被锁定 2 小时，请稍后再试。"></entry>
                 <entry key="EasyLockIPException" value="由于该IP连续登录错误，暂时被锁定 2 小时，请稍后再试。"></entry>
             </map>
         </property>
     	
     	<!-- 自定义拦截器，实现 EasyAuthenticationInterceptor 接口 -->
     	<property name="interceptor" ref="authenticationInterceptor"></property>
    </bean>
    
    <!-- specify LogoutFilter -->
    <!-- 能够实现会话安全信息(Subjec/Session)，RememberMe信息和AutoLogin自动登录信息的注销 -->
    <bean id="logout" class="cn.easyproject.easyshiro.EasyLogoutFilter">
    	<!-- specify logout redirectUrl -->
    	<property name="redirectUrl" value="/toLogin.action"></property>
    	<!-- EasyFormAuthenticationFilter -->
    	<property name="easyFormAuthenticationFilter" ref="auth"></property>
    </bean>
    
    <!-- perms -->
    <bean id="perms" class="cn.easyproject.easyshiro.EasyURLPermissionFilter">
    	<!-- 权限验证失败，转向的url -->
    	<property name="unauthorizedUrl" value="/toLogin.action"></property>
    	<!-- 是否开启登录超时检测; default is 'true'-->
    	<property name="authenticationTimeoutCheck" value="true"></property>
    	<!-- 权限验证失败，消息 key; default is 'MSG'  -->
    	<property name="msgKey" value="msg"></property>
    	<!-- 权限验证失败，状态码 key：301，登录超时; 401，权限拒绝; default is 'statusCode'  -->
    	<property name="statusCode" value="statusCode"></property>
    	<!-- 将消息存入session，session.setAttribute(MsgKey,xxxErrorMsg); default is 'false' -->
    	<property name="sessionMsg" value="true"></property>
    	<!-- 将消息存入request，request.setAttribute(MsgKey,xxxErrorMsg); default is 'false' -->
    	<property name="requestMsg" value="true"></property>
    	<!-- 认证失败提示内容;  default is 'Permission denied!' -->
    	<property name="permissionDeniedMsg" value="您没有权限"></property>
    	<!-- 登录超时提示内容; default is 'Your login has expired, please login again!' -->
    	<property name="authenticationTimeoutMsg" value="您的登录已过期，请重新登录！"></property>
    </bean>
    
    <!-- Shiro Native SessionManager -->
    <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
    	<!-- <property name="sessionMode" value="native"></property> -->
    	<property name="sessionManager" ref="sessionManager"></property>
    	<!-- Cache: EhCache-->
    	<property name="cacheManager" ref="shiroCacheManager"></property>
    	<property name="rememberMeManager" ref="rememberMeManager"></property>
    	<property name="realms">
    		<list>
    			<ref bean="jdbcRealm"/>
    		</list>
    	</property>
    </bean>
    
    <!-- shiroFilter -->
    <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
        <property name="securityManager" ref="securityManager"/>
        <!-- override these for application-specific URLs if you like:-->
        <property name="loginUrl" value="/toLogin.action"/>
        <property name="successUrl" value="/toMain.action"/>
        <property name="unauthorizedUrl" value="/toLogin.action"/> 
        <property name="filterChainDefinitions">
            <value>
                # anonymous
    			/checkCaptcha.action = anon
    			/notFound.action = anon
    			
                # requests to /DoLogout will be handled by the ‘logout’ filter
    			/logout.action = logout
    			
    			# requests to /toLogin.action will be handled by the ‘auth’ filter
    			/toLogin.action = auth
    			
    			# doc page need auth
    			/doc/** = auth
    			
    			# need to permission
    			/toMain.action = auth
    			/*.action =  perms
            </value>
        </property>
    </bean>
    
    <bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor"/>
</beans>
```



#### 2.2 Shiro INI 配置模板 shiro.ini
```properties
# -----------------------------------------------------------------------------
# Users and their (optional) assigned roles
# username = password, role1, role2, ..., roleN
# -----------------------------------------------------------------------------
[users]
#admin = admin123, admin
#jay = 123, user
#guest = guest, guest

# -----------------------------------------------------------------------------
# Roles with assigned permissions
# roleName = perm1, perm2, ..., permN
# -----------------------------------------------------------------------------
[roles]
#admin = *
#user = log:*


# -----------------------------------------------------------------------------
# Configuration SessionManager, Cache, Filter
# myFilter = com.company.web.some.FilterImplementation
# myFilter.property1 = value1
# -----------------------------------------------------------------------------

[main]
#- Session Manager
# securityManager.sessionManager.xxxx=xxxx

#-- Shiro Native SessionManager
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
# Use the configured native session manager:
securityManager.sessionManager = $sessionManager

#-- Session Timeout
# 3,600,000 milliseconds = 1 hour
securityManager.sessionManager.globalSessionTimeout = 3600000

#-- Session Listeners
# implement the SessionListener interface (or extend the convenience SessionListenerAdapter) 
# As the default SessionManager sessionListeners property is a collection, you can configure the SessionManager with one or more of your listener implementations like any other collection in shiro.ini:
#aSessionListener = com.foo.my.SessionListener
#anotherSessionListener = com.foo.my.OtherSessionListener
#securityManager.sessionManager.sessionListeners = $aSessionListener, $anotherSessionListener, etc.


#-- Custom Session IDs
# The default SessionIdGenerator is a JavaUuidSessionIdGenerator, 
# which generates String IDs based on Java UUIDs. 
#sessionIdGenerator = com.my.session.SessionIdGenerator
#securityManager.sessionManager.sessionDAO.sessionIdGenerator = $sessionIdGenerator


#-- SessionValidationScheduler
# Sessions are only validated to see 
# if they have been stopped or expired at the time they are accessed, 
# A SessionValidationScheduler is responsible for validating sessions 
# at a periodic rate to ensure they are cleaned up as necessary.
# You can custom SessionValidationScheduler implementation class.
sessionValidationScheduler = org.apache.shiro.session.mgt.ExecutorServiceSessionValidationScheduler
# Default is 3,600,000 millis = 1 hour:
sessionValidationScheduler.interval = 3600000
securityManager.sessionManager.sessionValidationScheduler = $sessionValidationScheduler
#securityManager.sessionManager.sessionValidationSchedulerEnabled = false


#-- Session DAO
# cache in the CacheManager should be used to store active sessions:
sessionDAO = org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO
securityManager.sessionManager.sessionDAO = $sessionDAO
# By default, the EnterpriseCacheSessionDAO asks the CacheManager 
# for a Cache named "shiro-activeSessionCache"
#sessionDAO.activeSessionsCacheName = ehcache_region_name


#- Cache
# securityManager.cacheManager

#-- EhCache
cacheManager = org.apache.shiro.cache.ehcache.EhCacheManager
cacheManager.cacheManagerConfigFile = classpath:ehcache.xml
##-- in-memory-only Cache
#cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager

#- RememeberMe(org.apache.shiro.web.mgt.CookieRememberMeManager)
securityManager.rememberMeManager.cookie.name = rememberMe
# default is /request.getContextPath()
securityManager.rememberMeManager.cookie.path = /
# default is ONE_YEAR
securityManager.rememberMeManager.cookie.maxAge = 31536000


#------------------------------ When use Session Clustering: Ehcache + Terracotta
#sessionDAO = org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO
## This name matches a cache name in ehcache.xml:
#sessionDAO.activeSessionsCacheName = shiro-activeSessionsCache
#securityManager.sessionManager.sessionDAO = $sessionDAO
#
## Configure The EhCacheManager:
#cacheManager = org.apache.shiro.cache.ehcache.EhCacheManager
#cacheManager.cacheManagerConfigFile = classpath:ehcache.xml
#
## Configure the above CacheManager on Shiro's SecurityManager
## to use it for all of Shiro's caching needs:
#securityManager.cacheManager = $cacheManager
#------------------------------ When use Session Clustering: Ehcache + Terracotta

#- Realm

#-- DataSource
dataSource=com.alibaba.druid.pool.DruidDataSource  
dataSource.url=jdbc:mysql://127.0.0.1:3306/easyssh
dataSource.username=root  
dataSource.password=root  
dataSource.initialSize=1
dataSource.minIdle=1 
dataSource.maxActive=20
dataSource.maxWait=60000
dataSource.timeBetweenEvictionRunsMillis=60000
dataSource.minEvictableIdleTimeMillis=300000
dataSource.validationQuery=SELECT 'x'
dataSource.testWhileIdle=true
dataSource.testOnBorrow=false
dataSource.testOnReturn=false
dataSource.poolPreparedStatements=false
dataSource.maxPoolPreparedStatementPerConnectionSize=20

#-- EasyJdbcRealm
#jdbcRealm=org.apache.shiro.realm.jdbc.JdbcRealm
jdbcRealm=cn.easyproject.easyshiro.EasyJdbcRealm
jdbcRealm.dataSource=$dataSource  
# 认证信息查询语句; default: select * from users where username = ?
jdbcRealm.authenticationQuery=select user_id as userid,name,password,status,real_name as realname from sys_user where name=? and status in(0,1)
# 密码列列名; default: password
jdbcRealm.passwordColumn=password
# 角色查询语句(支持多个username=?); default: select role_name from user_roles where username = ? 
jdbcRealm.userRolesQuery=select name from sys_role where role_id in (select role_id from sys_user_role where user_id=(select user_id from sys_user where name=?)) and status=0 
# 是否执行permissionsQuery权限查询; default: true
jdbcRealm.permissionsLookupEnabled=true
# 权限查询语句(支持多个username=?); default: select permission from roles_permissions where role_name = ?" 
jdbcRealm.permissionsQuery=select action from sys_menu_permission where MENU_PERMISSION_ID in( select MENU_PERMISSION_ID from sys_role_menu_permission where ROLE_ID in(select role_id from sys_user_role where user_id=(select user_id from sys_user where name=?))) UNION select action from sys_operation_permission where OPERATION_PERMISSION_ID in(select OPERATION_PERMISSION_ID from sys_role_operation_permission where ROLE_ID in(select role_id from sys_user_role where user_id=(select user_id from sys_user where name=?)))  
# EasyJdbcRealm 拦截器，可以认证和授权信息获得后，对SimpleAuthenticationInfo认证和SimpleAuthorizationInfo授权信息进行额外处理
jdbcRealm.interceptor=$realmInterceptor
# 自定义 EasyJdbcRealm 拦截器，可以认证和授权信息获得后，对SimpleAuthenticationInfo认证和SimpleAuthorizationInfo授权信息进行额外处理
realmInterceptor=cn.easyproject.easyee.ssh.sys.shiro.RealmInterceptor
jdbcRealm.interceptor=$realmInterceptor

securityManager.realms=$jdbcRealm 


#- auth Login Authentication

#-- 自定义 auth
#auth=cn.easyproject.easyshiro.EasyFormAuthenticationFilter
auth=cn.easyproject.easyshiro.EasyFormAuthenticationFilter
# specify login form page
# when request method is post execute login, else to login page view
auth.loginUrl = /toLogin.action
# redirect after successful login
auth.successUrl = /toMain.action
# name of request parameter with username; if not present filter assumes 'username'
auth.usernameParam = name
# name of request parameter with password; if not present filter assumes 'password'
auth.passwordParam = password
# does the user wish to be remembered?; if not present filter assumes 'rememberMe'
auth.rememberMeParam = rememberMe

#-- EasyFormAuthenticationFilter 自定义扩展属性
#---- Login Configuration
# 登录成功，将 token 存入 session 的 key; default is 'TOKEN'
# session.setAttribute(sessionTokenName,tokenObject); 
auth.sessionTokenKey= TOKEN
# 是否使用登录失败以重定向方式跳转回登录页面; default is 'false'
auth.loginFailureRedirectToLogin = true

#---- User defined UsernamePasswordToken Configuration
# 自定义 UsernamePasswordToken; Default is 'org.apache.shiro.auth.UsernamePasswordToken'
auth.tokenClassName=cn.easyproject.easyee.ssh.sys.shiro.UsernamePasswordEncodeToken

#---- CAPTCHA Configuration
# 是否开启验证码; default 'true'
auth.enableCaptcha=true
# 验证码参数名; default 'captcha'
auth.captchaParam = captcha
# Session中存储验证码值得可以; default 'captcha'
auth.sessionCaptchaKey = rand


#---------  AutoLogin Configuration 
# 是否开启自动登录 
auth.enableAutoLogin=false
# 自动登录参数数名 
auth.autoLoginParam=autoLogin
# Cookie maxAge ，default is ONE_YEAR 
auth.autoLoginMaxAge=31536000
# Cookie path，default is "" 
auth.autoLoginPath=/
# Cookie domain，empty or default is your current domain name 
#auth.autoLoginDomain=

#---- LockLogin Configuration 登录失败相关错误消息
# 是否开启LockLogin用户登录锁定；默认为false，不开启
auth.enableLockLogin=false
# Shiro CacheManager 
auth.ehCacheManager=$cacheManager
# LockLogin 管理锁定时间周期的 EHCache 缓存名称；默认为 shiro-lockLoginCache
auth.lockLoginCacheName=shiro-lockLoginCache
# LockLogin 统计登录错误次数时间周期的 EHCache 缓存名称；默认为 shiro-lockCheckCache 
auth.lockCheckCacheName=shiro-lockCheckCache
# 同一用户名登录达到登录错误次数，登录锁定；0为不限制；默认为6 
auth.userLock=4
#  同一IP登录达到错误次数，登录锁定；0为不限制；默认为15 
auth.ipLock=6
# 达到指定登录错误次数，显示验证码；-1为不控制验证码显示；默认为1 
auth.showCaptcha=2

#---- 登录失败相关错误消息
# 登录失败，消息 key 
auth.msgKey = MSG
# 将消息存入session，session.setAttribute(MsgKey,xxxErrorMsg); default is 'false'
auth.sessionMsg = true
# 将消息存入request，request.setAttribute(MsgKey,xxxErrorMsg); default is 'false'
auth.requestMsg = true
# 登录错误的，异常提示内容 Map
# ExceptionClassName:"Message", ExceptionClassName2:"Message2", ...
auth.exceptionMsg = LockedAccountException:"账户锁定，请联系管理员解锁。", AuthenticationException:"用户名，或密码有误！", EasyIncorrectCaptchaException:"验证码有误！", EasyLockUserException:"由于该用户连续登录错误，暂时被锁定 2 小时，请稍后再试。", EasyLockIPException:"由于该IP连续登录错误，暂时被锁定 2 小时，请稍后再试。"

#---- 自定义 EasyJdbcRealmInterceptor 拦截器，可以在认证成功或失败后进行自定义代码处理
authenticationInterceptor=cn.easyproject.easyee.ssh.sys.shiro.AuthenticationInterceptor
auth.interceptor=$authenticationInterceptor


#- user Authentication
# user filter, if not remeberMe redirected to the url, default is '/login.jsp'
user.loginUrl=/login.jsp

#- Logout
# specify LogoutFilter
# logout = org.apache.shiro.web.filter.authc.LogoutFilter
# specify logout redirectUrl
logout=cn.easyproject.easyshiro.EasyLogoutFilter
logout.redirectUrl = /login.jsp
# EasyFormAuthenticationFilter
logout.easyFormAuthenticationFilter=$auth

#- perms 
## 自定义基于 URL规则 授权过滤器
perms=cn.easyproject.easyshiro.EasyURLPermissionFilter
# 权限验证失败，转向的url
perms.unauthorizedUrl=/login.jsp
# 是否开启登录超时检测; default is 'true'
perms.authenticationTimeoutCheck= true

## 权限验证失败相关错误消息
# 权限验证失败，消息 key; default is 'msg' 
perms.msgKey = msg
# 权限验证失败，状态码 key：301，登录超时; 401，权限拒绝; default is 'statusCode' 
perms.statusCode = statusCode
# 将消息存入session，session.setAttribute(MsgKey,xxxErrorMsg); default is 'false'
perms.sessionMsg = true
# 将消息存入request，request.setAttribute(MsgKey,xxxErrorMsg); default is 'false'
perms.requestMsg = true
# 认证失败提示内容;  default is 'Permission denied!'
perms.permissionDeniedMsg = 您没有权限！
# 登录超时提示内容; default is 'Your login has expired, please login again!'
perms.authenticationTimeoutMsg = 您的登录已过期，请重新登录！


# -----------------------------------------------------------------------------
# Urls and their filter
# URL_Ant_Path_Expression = Path_Specific_Filter_Chain
# filter1[optional_config1], filter2[optional_config2], ..., filterN[optional_configN]
# -----------------------------------------------------------------------------
[urls]
 # anonymous
/checkCaptcha.action = anon
/notFound.action = anon

# requests to /DoLogout will be handled by the ‘logout’ filter
/logout.action = logout

# requests to /toLogin.action will be handled by the ‘auth’ filter
/toLogin.action = auth

# doc page need auth
/doc/** = auth

# need to permission
/toMain.action = auth
/*.action =  perms
```



## 组件详细功能

#### 1. EasyFormAuthenticationFilter：功能全面的表单登录认证过滤器，扩展了 `FormAuthenticationFilter`。
 - 登录成功 Token 存入Session
 
 - 重定向跳转支持（避免登录成功或失败后，刷新导致的重复提交无效登录请求）
 
 - 登录异常消息的配置支持（为不同异常自定义错误提示消息，并将错误信息保存到 request 和 session（重定向时）作用域）
 
 - CAPTCHA 验证码支持
 
 - AutoLogin 自动登录支持
 
 - LockLogin 登录锁定支持
 
 - `EasyAuthenticationInterceptor` 认证成功与失败拦截器支持（例如，可以在认证成功后进行用户锁定检测，或进行菜单查询初始化等扩展工作。）
 
 - 已登陆用户重新登录账户（Shrio默认一个浏览器已登录情况下，登陆新账户会自动跳转到原登录页面）
 
 - 继承的 RememberMe 支持（使用内置 user 过滤器实现，Shiro默认的 RememberMe 不是用来自动登录，而是用于 user 过滤器）





#### 2. EasyLogoutFilter： 用户注销过滤器，扩展了 `LogoutFilter`。

- 能够实现会话安全信息(Subjec/Session)，RememberMe信息和AutoLogin自动登录信息的注销。




####  3. EasyUsernamePasswordEndcodeToken：简化并方案更加灵活的密码加密Token，扩展了 `UsernamePasswordToken`。

- 简化了登录时的密码加密处理，只需继承 `EasyUsernamePasswordEndcodeToken`，自行实现 `encodePassword()` 密码加密逻辑，即可返回密码加密后的结果

- 能够添自定义属性，使用 `EasyJdbcRealm` 登录认证时，自动将登录查询语句相关的用户数据库列值赋值给类的同名属性（`encodePassword()`加密时可以使用数据库列属性作为加密 `salt`）





#### 4. EasyJdbcRealm：通用的数据库认证，角色，权限查询Realm，扩展了 `AuthorizingRealm`。

- 在 `doGetAuthenticationInfo` 用户登录认证时，能将查询语句查询的用户在数据库的信息，全部自动初始化到登录认证 Token `UsernamePasswordToken` 子类的扩展同名属性中，解决了认证信息不包含数据库用户属性的问题

- 提供了静态的 `reloadPermissions` 方法，**可以在认证成功后直接刷新权限**（例如：重新分配用户权限后，刷新当前用户的最新权限。）

- `EasyJdbcRealmInterceptor` 认证与授权信息拦截器（例如，可以在获取授权或认证信息后，对进行二次处理，如对特定字符分割的权限字符串进行分割后重新存入 `StringPermissions` 等等。）

- 兼容 `UsernamePasswordToken` 和 `EasyUsernamePasswordEndcodeToken` 的登录认证

- 提供EasyJdbcRealm，扩展 JdbcRealm, 解决了认证信息不包含数据库用户属性的问题。
能够在登录认证时，将用户在数据库的信息，全部自动封装到用户登录认证的Token(EasyUsernamePasswordToken)中。


#### 5. EasyURLPermissionFilter：基于 URL 规则是否匹配的授权判断 Perms，扩展了 `PermissionsAuthorizationFilter`。

- 如果权限字符串（`StringPermissions`）中有该 URL 字符串，则允许访问，否则不允许

- 支持登录超时检测

- 支持**Ajax 响应**，Ajax 请求权限不足或登录超时时使用 JSON 输出（消息可通过 `permissionDeniedMsg`, `authenticationTimeoutMsg` 配置自定义）：
```JSON
{ "MSG":"您没有权限！","statusCode":"401" }
{ "MSG":"您的登录已过期，请重新登录！","statusCode":"301" }
```


#### 6. 登录认证相关自定义异常

- `EasyIncorrectCaptchaException`，验证码错误异常，扩展了 `AuthenticationException`

- `EasyLockLoginException`，登录锁定异常父类，扩展了 `AuthenticationException`

- `EasyLockIPException`，IP锁定异常，扩展了 `EasyLockLoginException`

- `EasyLockUserException`，用户锁定异常，扩展了 `EasyLockLoginException`


#### 7. 拦截器支持

- `EasyAuthenticationInterceptor`，用户认证成功或识别拦截器（例如，可以在认证成功后进行用户锁定检测，或进行菜单查询初始化等扩展工作。）

- `EasyJdbcRealmInterceptor`， 认证与授权信息拦截器（例如，可以在获取授权或认证信息后，对进行二次处理，如对特定字符分割的权限字符串进行分割后重新存入 `StringPermissions` 等等。）




## 其他功能配置

- ### 权限刷新
`EasyJdbcRealm` 提供了静态的 `reloadPermissions` 方法，可以在认证成功后直接刷新权限（例如：重新分配用户权限后，刷新当前用户的最新权限。）

- ### 登录消息提示管理
 EasyFormAuthenticationFilter 能够按照异常配置相应错误提示信息，并根据配置保存进 request 或 session。

 #### 1. 错误消息自定义配置
 ```XML
 <!-- ## 登录失败相关错误消息 ## -->
 <!-- 登录失败，消息 key  -->
 <property name="msgKey" value="MSG"></property>
 <!-- 将消息存入session，session.setAttribute(MsgKey,xxxErrorMsg); default is 'false' -->
 <property name="sessionMsg" value="true"></property>
 <!-- 将消息存入request，request.setAttribute(MsgKey,xxxErrorMsg); default is 'false' -->
 <property name="requestMsg" value="true"></property>
 <!-- # 登录错误的，异常提示内容 Map-->
 <property name="exceptionMsg">
     <map>
         <!-- ExceptionClassName:"Message", ExceptionClassName2:"Message2", ... -->
         <entry key="LockedAccountException" value="账户锁定，请联系管理员解锁。"></entry>
         
         <entry key="AuthenticationException" value="用户名或密码有误！"></entry>
         
         <entry key="EasyIncorrectCaptchaException" value="验证码有误！"></entry>
         <entry key="EasyLockUserException" value="由于该用户连续登录错误，暂时被锁定 2 小时，请稍后再试。"></entry>
         <entry key="EasyLockIPException" value="由于该IP连续登录错误，暂时被锁定 2 小时，请稍后再试。"></entry>
     </map>
 </property>
 ```
 ```
 #---- 登录失败相关错误消息
 # 登录失败，消息 key 
 auth.msgKey = MSG
 # 将消息存入session，session.setAttribute(MsgKey,xxxErrorMsg); default is 'false'
 auth.sessionMsg = true
 # 将消息存入request，request.setAttribute(MsgKey,xxxErrorMsg); default is 'false'
 auth.requestMsg = true
 # 登录错误的，异常提示内容 Map
 # ExceptionClassName:"Message", ExceptionClassName2:"Message2", ...
 auth.exceptionMsg = LockedAccountException:"账户锁定，请联系管理员解锁。", AuthenticationException:"用户名，或密码有误！", EasyIncorrectCaptchaException:"验证码有误！", EasyLockUserException:"由于该用户连续登录错误，暂时被锁定 2 小时，请稍后再试。", EasyLockIPException:"由于该IP连续登录错误，暂时被锁定 2 小时，请稍后再试。"
 ```
 
 #### 2. 页面消息提醒示例
 ```
 <!-- 登录消息提示JS -->
 <s:if test="#session.MSG!=null">
 	<script type="text/javascript">
 		$(function() {
 			uiEx.alert("${MSG }", "info");
 		})
 	</script>
 	<s:set name="MSG" scope="session" value=""></s:set>
 </s:if>
 ```


## LockLogin 登录锁定

`EasyFormAuthenticationFilter` 提供了基于 `EhCache` 的 LockLogin 登录锁定功能。

### 1. ehcache.xml 配置

使用LockLogin, 必须配置登录锁定相关的 EhCache 缓存配置 `shiro-lockLoginCache`，`shiro-lockCheckCache`。

  ```XML
  <!-- ## LockLogin Configuration ## -->
  <!-- LockLogin 管理锁定时间周期的 EHCache 缓存名称-->
  <!-- 只需调整timeToIdleSeconds，默认达到登录锁定次数，登录锁定  2 小时 -->
  <!-- LockLogin name cache management locks EHCache time period-->
  <!-- Simply adjust timeToIdleSeconds, the default number of times to reach the login lockout, login lockout 2 Hours-->
  <cache
     	    name="shiro-lockLoginCache"
          maxElementsInMemory="100000"
          eternal="false"
          timeToIdleSeconds="0"
          timeToLiveSeconds="7200"
          diskExpiryThreadIntervalSeconds="600"
          memoryStoreEvictionPolicy="LRU"
          overflowToDisk="true"
          diskPersistent="true">
  </cache>
    
   <!-- LockLogin 统计登录错误次数时间周期的 EHCache 缓存名称 -->
   <!-- 只需调整timeToIdleSeconds，默认统计 10 分钟内的错误次数  -->
   <!-- EHCache caching name Lock Login login error statistics of the number of time periods -->
   <!-- Simply adjust timeToIdleSeconds, default statistics the number of errors in 10 minutes -->
   <cache
   	    name="shiro-lockCheckCache"
        maxElementsInMemory="100000"
        eternal="false"
        timeToIdleSeconds="0"
        timeToLiveSeconds="600"
        diskExpiryThreadIntervalSeconds="600"
        memoryStoreEvictionPolicy="LRU"
        overflowToDisk="true"
        diskPersistent="true">
	</cache>
  ```

### 2. LockLogin 控制

- 基于用户名（User）的锁定控制
- 基于 IP 的锁定控制
- 基于 IP 的验证码是否显示控制
 
 ```XML
 <!-- 是否开启LockLogin用户登录锁定；默认为false，不开启 -->
 <property name="enableLockLogin" value="true"></property>
 <!-- Shiro CacheManager -->
 <property name="ehCacheManager" ref="shiroCacheManager"></property>
 <!-- LockLogin 管理锁定时间周期的 EHCache 缓存名称；默认为 shiro-lockLoginCache -->
 <property name="lockLoginCacheName" value="shiro-lockLoginCache"></property>
 <!-- LockLogin 统计登录错误次数时间周期的 EHCache 缓存名称；默认为 shiro-lockCheckCache -->
 <property name="lockCheckCacheName" value="shiro-lockCheckCache"></property>
 <!-- 同一用户名登录达到登录错误次数，登录锁定；0为不限制；默认为6 -->
 <property name="userLock" value="4"></property>
 <!--  同一IP登录达到错误次数，登录锁定；0为不限制；默认为15 -->
 <property name="ipLock" value="6"></property>
 <!-- 达到指定登录错误次数，显示验证码；-1为不控制验证码显示；默认为1 -->
 <property name="showCaptcha" value="1"></property>
 ```
 ```
 #---- LockLogin Configuration 登录失败相关错误消息
 # 是否开启LockLogin用户登录锁定；默认为false，不开启
 auth.enableLockLogin=false
 # Shiro CacheManager 
 auth.ehCacheManager=$cacheManager
 # LockLogin 管理锁定时间周期的 EHCache 缓存名称；默认为 shiro-lockLoginCache
 auth.lockLoginCacheName=shiro-lockLoginCache
 # LockLogin 统计登录错误次数时间周期的 EHCache 缓存名称；默认为 shiro-lockCheckCache 
 auth.lockCheckCacheName=shiro-lockCheckCache
 # 同一用户名登录达到登录错误次数，登录锁定；0为不限制；默认为6 
 auth.userLock=4
 #  同一IP登录达到错误次数，登录锁定；0为不限制；默认为15 
 auth.ipLock=6
 # 达到指定登录错误次数，显示验证码；-1为不控制验证码显示；默认为1 
 auth.showCaptcha=2
 ```

### 3. 锁定判断

EasyShiro 的 `EasyFormAuthenticationFilter` 过滤器在跳转到登录页面时已经检测了是否需要显示验证码或IP是否锁定，并将信息存入 `Session`。在页面可以从 `Session` 中获取判断信息。

- IP 是否锁定 `session.IPLock`
```
<s:if test="#session.IPLock!=null">
	<span style="color:#ff0000; font-weight:bold">您的 IP 地址由于连续登录错误过多，已被锁定 2 小时，请稍后再试。</span>
</s:if>
```

- 是否需要显示验证码 `session.ShowCAPTCHA`
```
<s:if test="#session.ShowCAPTCHA!=null"> 
     <tr>
          <td>Verification:</td>
          <td>
                <input class="easyui-validatebox textbox"
                id="captcha" name="captcha"   
                style="height:30px;width: 80px;" data-options="required:true, validType:'minLength[4]' , tipPosition:'right',position:'bottom', deltaX:105"
                maxlength="4"></input> 
                <div style="display: none; float: right; border: 1px solid #ccc;" id="vcTr">
                     <img  title="点击切换" alt="加载中..." align="middle"
                     style="cursor: pointer;" width="100" height="28" id="vcImg" src="jsp/VerifyCode.jsp">
                </div>
          </td>
     </tr>   
</s:if>  
```

### 4. 登录锁定解锁系统 LockLoginManagement
- 将 `locklogin` 放入 web 根目录，访问即可:
```
http://127.0.0.1:8088/easyee-ssh/locklogin/admin.jsp
```
- 默认缓存代码如下，您可根据需要进行修改
```
String lockLogin="shiro-lockLoginCache";
String lockLCheck="shiro-lockCheckCache";
```
- `locklogin/admin.jsp` 并没有进行权限控制，注意使用时进行访问控制

 ![LockLogin](images/locklogin1.png)
 
 ![LockLogin](images/locklogin2.png)
 
 ![LockLogin](images/locklogin3.png)
 
 ![LockLogin](images/locklogin4.png)
 
 ![LockLogin](images/locklogin5.png)





## END
### [官方主页](http://www.easyproject.cn/easyshiro/zh-cn/index.jsp '官方主页')

[留言评论](http://www.easyproject.cn/easyshiro/zh-cn/index.jsp#donation '留言评论')

如果您有更好意见，建议或想法，请联系我。

### [The official home page](http://www.easyproject.cn/easyshiro/en/index.jsp 'The official home page')

[Comments](http://www.easyproject.cn/easyshiro/en/index.jsp#donation 'Comments')

If you have more comments, suggestions or ideas, please contact me.



Email：<inthinkcolor@gmail.com>

[http://www.easyproject.cn](http://www.easyproject.cn "EasyProject Home")



**支付宝钱包扫一扫捐助：**

我们相信，每个人的点滴贡献，都将是推动产生更多、更好免费开源产品的一大步。

**感谢慷慨捐助，以支持服务器运行和鼓励更多社区成员。**

<img alt="支付宝钱包扫一扫捐助" src="http://www.easyproject.cn/images/s.png"  title="支付宝钱包扫一扫捐助"  height="256" width="256"></img>



We believe that the contribution of each bit by bit, will be driven to produce more and better free and open source products a big step.

**Thank you donation to support the server running and encourage more community members.**

[![PayPal](http://www.easyproject.cn/images/paypaldonation5.jpg)](https://www.paypal.me/easyproject/10 "Make payments with PayPal - it's fast, free and secure!")

