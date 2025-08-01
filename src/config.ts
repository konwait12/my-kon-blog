// import type {
// 	ExpressiveCodeConfig,
// 	LicenseConfig,
// 	NavBarConfig,
// 	ProfileConfig,
// 	SiteConfig,
// } from "./types/config";
// import { LinkPreset } from "./types/config";

// export const siteConfig: SiteConfig = {
// 	title: "Fuwari",
// 	subtitle: "Demo Site",
// 	lang: "en", // 'en', 'zh_CN', 'zh_TW', 'ja', 'ko', 'es', 'th', 'vi'
// 	themeColor: {
// 		hue: 250, // Default hue for the theme color, from 0 to 360. e.g. red: 0, teal: 200, cyan: 250, pink: 345
// 		fixed: false, // Hide the theme color picker for visitors
// 	},
// 	banner: {
// 		enable: false,
// 		src: "assets/images/demo-banner.png", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
// 		position: "center", // Equivalent to object-position, only supports 'top', 'center', 'bottom'. 'center' by default
// 		credit: {
// 			enable: false, // Display the credit text of the banner image
// 			text: "", // Credit text to be displayed
// 			url: "", // (Optional) URL link to the original artwork or artist's page
// 		},
// 	},
// 	toc: {
// 		enable: true, // Display the table of contents on the right side of the post
// 		depth: 2, // Maximum heading depth to show in the table, from 1 to 3
// 	},
// 	favicon: [
// 		// Leave this array empty to use the default favicon
// 		// {
// 		//   src: '/favicon/icon.png',    // Path of the favicon, relative to the /public directory
// 		//   theme: 'light',              // (Optional) Either 'light' or 'dark', set only if you have different favicons for light and dark mode
// 		//   sizes: '32x32',              // (Optional) Size of the favicon, set only if you have favicons of different sizes
// 		// }
// 	],
// };

// export const navBarConfig: NavBarConfig = {
// 	links: [
// 		LinkPreset.Home,
// 		LinkPreset.Archive,
// 		LinkPreset.About,
// 		{
// 			name: "GitHub",
// 			url: "https://github.com/saicaca/fuwari", // Internal links should not include the base path, as it is automatically added
// 			external: true, // Show an external link icon and will open in a new tab
// 		},
// 	],
// };

// export const profileConfig: ProfileConfig = {
// 	avatar: "assets/images/demo-avatar.png", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
// 	name: "Lorem Ipsum",
// 	bio: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
// 	links: [
// 		{
// 			name: "Twitter",
// 			icon: "fa6-brands:twitter", // Visit https://icones.js.org/ for icon codes
// 			// You will need to install the corresponding icon set if it's not already included
// 			// `pnpm add @iconify-json/<icon-set-name>`
// 			url: "https://twitter.com",
// 		},
// 		{
// 			name: "Steam",
// 			icon: "fa6-brands:steam",
// 			url: "https://store.steampowered.com",
// 		},
// 		{
// 			name: "GitHub",
// 			icon: "fa6-brands:github",
// 			url: "https://github.com/saicaca/fuwari",
// 		},
// 	],
// };

// export const licenseConfig: LicenseConfig = {
// 	enable: true,
// 	name: "CC BY-NC-SA 4.0",
// 	url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
// };

// export const expressiveCodeConfig: ExpressiveCodeConfig = {
// 	// Note: Some styles (such as background color) are being overridden, see the astro.config.mjs file.
// 	// Please select a dark theme, as this blog theme currently only supports dark background color
// 	theme: "github-dark",
// };

// 导入配置相关的类型定义
import type {
	ExpressiveCodeConfig,
	LicenseConfig,
	NavBarConfig,
	ProfileConfig,
	SiteConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

/**
 * 站点基本配置
 * 用于设置博客的整体信息和全局样式
 */
export const siteConfig: SiteConfig = {
	title: "my-kon-blog", // 博客标题
	subtitle: "kon永不毕业-myblog", // 博客副标题（补充说明）
	lang: "zh_CN", // 站点默认语言，可选值：'en', 'zh_CN', 'zh_TW', 'ja', 'ko', 'es', 'th', 'vi'
	themeColor: {
		hue: 250, // 主题色调（色相值），0-360之间。例如：红色0，青绿色200，青色250，粉色345
		fixed: false, // 是否固定主题色（true则隐藏访客的主题色选择器）
	},
	banner: {
		enable: true, // 是否启用顶部横幅图片
		src: "assets/images/hf.jpg", // 横幅图片路径（相对于/src目录；若以'/'开头则相对于/public目录）
		position: "center", // 图片显示位置，支持'top'（顶部）、'center'（居中）、'bottom'（底部），默认居中
		credit: {
			enable: false, // 是否显示图片版权信息
			text: "", // 版权文本内容
			url: "", // （可选）图片来源或作者页面的链接
		},
	},
	toc: {
		enable: true, // 是否在文章右侧显示目录
		depth: 2, // 目录显示的最大标题层级，1-3之间
	},
	favicon: [
		// 网站图标配置，留空则使用默认图标
		// 示例配置：
		// {
		//   src: '/favicon/icon.png',    // 图标路径（相对于/public目录）
		//   theme: 'light',              // （可选）指定主题模式，'light'或'dark'，用于明暗模式显示不同图标
		//   sizes: '32x32',              // （可选）图标尺寸，用于适配不同设备
		// }
	],
};

/**
 * 导航栏配置
 * 定义顶部导航菜单的链接
 */
export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home, // 预设的"首页"链接
		LinkPreset.Archive, // 预设的"归档"链接
		LinkPreset.About, // 预设的"关于"链接
		{
			name: "GitHub", // 链接名称
			url: "https://github.com/saicaca/fuwari", // 链接地址（内部链接无需包含基础路径，会自动添加）
			external: true, // 是否为外部链接（true会显示外部链接图标并在新标签页打开）
		},
	],
};

/**
 * 个人资料配置
 * 用于侧边栏或首页显示的个人信息
 */
export const profileConfig: ProfileConfig = {
	avatar: "assets/images/kon2.png", // 头像图片路径（相对于/src目录；若以'/'开头则相对于/public目录）
	name: "k-on!--wait", // 显示的姓名/昵称
	bio: "小白中的菜.", // 个人简介
	links: [
		{
			name: "Twitter", // 社交平台名称
			icon: "fa6-brands:twitter", // 图标代码（可从https://icones.js.org/查询）
			// 若图标集未包含，需先安装：`pnpm add @iconify-json/<图标集名称>`
			url: "https://twitter.com", // 社交账号链接
		},
		{
			name: "Steam",
			icon: "fa6-brands:steam",
			url: "https://store.steampowered.com",
		},
		{
			name: "GitHub",
			icon: "fa6-brands:github",
			url: "https://github.com/konwait12",
		},
	],
};

/**
 * 版权信息配置
 * 用于文章底部显示的版权声明
 */
export const licenseConfig: LicenseConfig = {
	enable: true, // 是否显示版权信息
	name: "CC BY-NC-SA 4.0", // 版权协议名称
	url: "https://creativecommons.org/licenses/by-nc-sa/4.0/", // 版权协议详情链接
};

/**
 * 代码展示配置
 * 用于设置代码块的显示样式
 */
export const expressiveCodeConfig: ExpressiveCodeConfig = {
	// 注意：部分样式（如背景色）可能在astro.config.mjs中被覆盖
	// 请选择暗色主题，因为当前博客主题仅支持深色背景
	theme: "github-dark", // 代码块主题
};
